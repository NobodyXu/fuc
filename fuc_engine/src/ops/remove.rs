use std::{borrow::Cow, fmt::Debug, fs, io, path::Path};

use typed_builder::TypedBuilder;

use crate::{
    ops::{compat::DirectoryOp, IoErr},
    Error,
};

/// Removes a file or directory at this path, after removing all its contents.
///
/// This function does **not** follow symbolic links: it will simply remove
/// the symbolic link itself.
///
/// # Errors
///
/// Returns the underlying I/O errors that occurred.
pub fn remove_file<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    RemoveOp::builder()
        .files([Cow::Borrowed(path.as_ref())])
        .build()
        .run()
}

#[derive(TypedBuilder, Debug)]
pub struct RemoveOp<'a, F: IntoIterator<Item = Cow<'a, Path>>> {
    files: F,
    #[builder(default = false)]
    force: bool,
    #[builder(default = true)]
    preserve_root: bool,
}

impl<'a, F: IntoIterator<Item = Cow<'a, Path>>> RemoveOp<'a, F> {
    /// Consume and run this remove operation.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O errors that occurred.
    pub fn run(self) -> Result<(), Error> {
        let remove = compat::remove_impl();
        let result = schedule_deletions(self, &remove);
        remove.finish().and(result)
    }
}

fn schedule_deletions<'a>(
    RemoveOp {
        files,
        force,
        preserve_root,
    }: RemoveOp<'a, impl IntoIterator<Item = Cow<'a, Path>>>,
    remove: &impl DirectoryOp<Cow<'a, Path>>,
) -> Result<(), Error> {
    for file in files {
        if preserve_root && file == Path::new("/") {
            return Err(Error::PreserveRoot);
        }
        let is_dir = match file.metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if force {
                    continue;
                }

                return Err(Error::NotFound {
                    file: file.into_owned(),
                });
            }
            r => r,
        }
        .map_io_err(|| format!("Failed to read metadata for file: {file:?}"))?
        .is_dir();

        if is_dir {
            remove.run(file)?;
        } else {
            fs::remove_file(&file).map_io_err(|| format!("Failed to delete file: {file:?}"))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod compat {
    use std::{
        borrow::Cow,
        cell::RefCell,
        ffi::{CStr, CString},
        num::NonZeroUsize,
        os::fd::{AsRawFd, RawFd},
        path::Path,
        sync::Arc,
        thread,
        thread::JoinHandle,
    };

    use crossbeam_channel::{Receiver, Sender};
    use io_uring::{
        opcode::{Nop, UnlinkAt},
        squeue::Flags,
        types::Fd,
        IoUring,
    };
    use linux_raw_sys::general::linux_dirent64;
    use rustix::fs::{cwd, openat, unlinkat, AtFlags, Mode, OFlags};

    use crate::{
        ops::{compat::DirectoryOp, concat_cstrs, path_buf_to_cstring, IoErr, LazyCell},
        Error,
    };

    struct Impl<LF: FnOnce() -> (Sender<Message>, JoinHandle<Result<(), Error>>)> {
        #[allow(clippy::type_complexity)]
        scheduling: LazyCell<(Sender<Message>, JoinHandle<Result<(), Error>>), LF>,
    }

    pub fn remove_impl<'a>() -> impl DirectoryOp<Cow<'a, Path>> {
        let scheduling = LazyCell::new(|| {
            let (tx, rx) = crossbeam_channel::unbounded();
            (tx, thread::spawn(|| root_worker_thread(rx)))
        });

        Impl { scheduling }
    }

    impl<LF: FnOnce() -> (Sender<Message>, JoinHandle<Result<(), Error>>)>
        DirectoryOp<Cow<'_, Path>> for Impl<LF>
    {
        fn run(&self, dir: Cow<Path>) -> Result<(), Error> {
            let (tasks, _) = &*self.scheduling;
            tasks
                .send(Message::Node(TreeNode {
                    path: path_buf_to_cstring(dir.into_owned())?,
                    _parent: None,
                    messages: tasks.clone(),
                }))
                .map_err(|_| Error::Internal)
        }

        fn finish(self) -> Result<(), Error> {
            if let Some((tasks, thread)) = self.scheduling.into_inner() {
                drop(tasks);
                thread.join().map_err(|_| Error::Join)??;
            }
            Ok(())
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn root_worker_thread(tasks: Receiver<Message>) -> Result<(), Error> {
        let mut available_parallelism = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
            - 1;

        thread::scope(|scope| {
            let mut threads = Vec::with_capacity(available_parallelism);

            let mut io_uring = {
                let uring = IoUring::new(256).unwrap();
                uring
                    .submitter()
                    .register_iowq_max_workers(&mut [1, 1])
                    .unwrap();
                uring
            };
            let io_uring_fd = io_uring.as_raw_fd();
            for message in &tasks {
                if available_parallelism > 0 {
                    available_parallelism -= 1;
                    threads.push(scope.spawn({
                        let tasks = tasks.clone();
                        move || worker_thread(tasks, io_uring_fd)
                    }));
                }

                match message {
                    Message::Node(node) => delete_dir(node, &mut io_uring)?,
                    Message::Error(e) => return Err(e),
                }
            }

            for thread in threads {
                thread.join().map_err(|_| Error::Join)??;
            }
            Ok(())
        })
    }

    fn worker_thread(tasks: Receiver<Message>, i: RawFd) -> Result<(), Error> {
        let mut io_uring = {
            let uring = IoUring::builder().setup_attach_wq(i).build(256).unwrap();
            uring
                .submitter()
                .register_iowq_max_workers(&mut [1, 1])
                .unwrap();
            uring
        };
        for message in tasks {
            match message {
                Message::Node(node) => delete_dir(node, &mut io_uring)?,
                Message::Error(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn delete_dir(node: TreeNode, io_uring: &mut IoUring) -> Result<(), Error> {
        thread_local! {
            static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(8192));
        }

        BUF.with(|buf| {
            let dir = openat(
                cwd(),
                node.path.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_io_err(|| format!("Failed to open directory: {:?}", node.path))?;

            let node = LazyCell::new(|| Arc::new(node));
            let mut buf = buf.borrow_mut();
            let buf = buf.spare_capacity_mut();

            let mut offset = 0;
            let mut initialized = 0;
            let mut pending = 0;
            loop {
                // if io_uring.submission().is_full() {
                //     unsafe {
                //         io_uring
                //             .submission()
                //             .push(&Nop::new().build().flags(Flags::IO_DRAIN))
                //             .unwrap();
                //     }
                //     io_uring.submit_and_wait(1).unwrap();
                //     for entry in io_uring.completion() {
                //         assert_eq!(entry.result(), 0);
                //     }
                //     pending = 0;
                // }

                if offset < initialized {
                    let dirent_ptr = buf[offset..].as_ptr();
                    // SAFETY:
                    // - This data is initialized by the check above.
                    //   - Assumption: the kernel will not give us partial structs.
                    // - Assumption: the kernel uses proper alignment between structs.
                    // - The starting pointer is aligned (performed in RawDir::new)
                    let dirent = unsafe { &*dirent_ptr.cast::<linux_dirent64>() };

                    offset += usize::from(dirent.d_reclen);

                    let file_name = unsafe { CStr::from_ptr(dirent.d_name.as_ptr().cast()) };

                    // TODO here and other uses: https://github.com/rust-lang/rust/issues/105723
                    const DOT: &CStr = CStr::from_bytes_with_nul(b".\0").ok().unwrap();
                    const DOT_DOT: &CStr = CStr::from_bytes_with_nul(b"..\0").ok().unwrap();

                    if file_name == DOT || file_name == DOT_DOT {
                        continue;
                    }

                    if dirent.d_type == 4 {
                        node.messages
                            .send(Message::Node(TreeNode {
                                path: concat_cstrs(&node.path, file_name),
                                _parent: Some(node.clone()),
                                messages: node.messages.clone(),
                            }))
                            .map_err(|_| Error::Internal)?;
                    } else {
                        pending += 1;
                        unsafe {
                            io_uring
                                .submission()
                                .push(
                                    &UnlinkAt::new(Fd(dir.as_raw_fd()), file_name.as_ptr())
                                        .build()
                                        .flags(Flags::ASYNC),
                                )
                                .unwrap();
                        }
                    }

                    continue;
                }

                if pending > 0 {
                    io_uring.submit_and_wait(pending).unwrap();
                    for entry in io_uring.completion() {
                        assert_eq!(entry.result(), 0);
                    }
                    pending = 0;
                }

                offset = 0;

                match unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        dir.as_raw_fd(),
                        buf.as_mut_ptr(),
                        buf.len(),
                    )
                } {
                    bytes_read if bytes_read == 0 => break,
                    bytes_read => initialized = bytes_read as usize,
                }
            }
            Ok(())
        })
    }

    enum Message {
        Node(TreeNode),
        Error(Error),
    }

    struct TreeNode {
        path: CString,
        // Needed for the recursive drop implementation
        _parent: Option<Arc<TreeNode>>,
        messages: Sender<Message>,
    }

    impl Drop for TreeNode {
        fn drop(&mut self) {
            if let Err(e) = unlinkat(cwd(), self.path.as_c_str(), AtFlags::REMOVEDIR)
                .map_io_err(|| format!("Failed to delete directory: {:?}", self.path))
            {
                // If the receiver closed, then another error must have already occurred.
                drop(self.messages.send(Message::Error(e)));
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod compat {
    use std::{borrow::Cow, fs, io, path::Path};

    use rayon::prelude::*;

    use crate::{
        ops::{compat::DirectoryOp, IoErr},
        Error,
    };

    struct Impl;

    pub fn remove_impl<'a>() -> impl DirectoryOp<Cow<'a, Path>> {
        Impl
    }

    impl DirectoryOp<Cow<'_, Path>> for Impl {
        fn run(&self, dir: Cow<Path>) -> Result<(), Error> {
            remove_dir_all(&dir).map_io_err(|| format!("Failed to delete directory: {dir:?}"))
        }

        fn finish(self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
        let path = path.as_ref();
        path.read_dir()?
            .par_bridge()
            .try_for_each(|dir_entry| -> io::Result<()> {
                let dir_entry = dir_entry?;
                if dir_entry.file_type()?.is_dir() {
                    remove_dir_all(dir_entry.path())?;
                } else {
                    fs::remove_file(dir_entry.path())?;
                }
                Ok(())
            })?;
        fs::remove_dir(path)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod compat {
    use std::{borrow::Cow, path::Path};

    use remove_dir_all::remove_dir_all;

    use crate::{
        ops::{compat::DirectoryOp, IoErr},
        Error,
    };

    struct Impl;

    pub fn remove_impl<'a>() -> impl DirectoryOp<Cow<'a, Path>> {
        Impl
    }

    impl DirectoryOp<Cow<'_, Path>> for Impl {
        fn run(&self, dir: Cow<Path>) -> Result<(), Error> {
            remove_dir_all(&dir).map_io_err(|| format!("Failed to delete directory: {dir:?}"))
        }

        fn finish(self) -> Result<(), Error> {
            Ok(())
        }
    }
}

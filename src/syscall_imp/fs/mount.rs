use alloc::vec::Vec;
use core::ffi::c_char;
use arceos_posix_api::{FilePath, AT_FDCWD};
use axerrno::AxError;
use axfs::api::set_current_dir;
use axsync::Mutex;
use crate::ptr::{PtrWrapper, UserConstPtr};
use crate::syscall_body;

/// mount() attaches the filesystem specified by source (which is
/// often a pathname referring to a device, but can also be the
/// pathname of a directory or file, or a dummy string) to the
/// location (a directory or file) specified by the pathname in
/// target.
///
/// # Arguments
/// * `special` - pathname referring to a device
/// * `dir` - target pathname
/// * `fstype` - file system type
/// * `flags` - mount flags
/// * `data` - a string of comma-separated options understood by this filesystem
pub(crate) fn sys_mount(
    special: UserConstPtr<u8>,
    dir: UserConstPtr<u8>,
    fstype: UserConstPtr<u8>,
    _flags: u64,
    _data: UserConstPtr<u8>
) -> i64 {
   syscall_body!(sys_mount, {
       let special_path = arceos_posix_api::handle_file_path(AT_FDCWD, Some(special.get()?), false)
            .inspect_err(|err| log::error!("mount: special: {:?}", err))?;
       if special_path.is_dir() {
           log::debug!("mount: special is a directory");
           return Err(axerrno::LinuxError::EINVAL);
       }
        
       let _ = set_current_dir("/musl/basic/");
        
       let dir_path = arceos_posix_api::handle_file_path(AT_FDCWD, Some(dir.get()?), true)
            .inspect_err(|err| log::error!("mount: dir: {:?}", err))?;
       let fstype_str = arceos_posix_api::char_ptr_to_str(fstype.get()? as *const c_char)
            .inspect_err(|err| log::error!("mount: fstype: {:?}", err))
            .map_err(|_| AxError::InvalidInput)?;
       
       if fstype_str != "vfat" {
           log::debug!("mount: fstype is not axfs");
           return Err(axerrno::LinuxError::EINVAL);
       }
       
       if !dir_path.exists() {
            debug!("mount path not exist");
            return Err(axerrno::LinuxError::EPERM);
        }

       
       if check_mounted(&dir_path) {
           debug!("mount path includes mounted fs");
           return Err(axerrno::LinuxError::EPERM);
       }
       
       if !mount_fat_fs(&special_path, &dir_path) {
           debug!("mount error");
           return Err(axerrno::LinuxError::EPERM);
       }
       Ok(0)
   })
    
}

/// umount() remove the attachment of the (topmost)
/// filesystem mounted on target.
///
/// # Arguments
/// * `special` - pathname the file system mounting on
/// * `flags` - mount flags
pub(crate) fn sys_umount2(special: UserConstPtr<u8>, flags: i32) -> i64 {
    syscall_body!(sys_umount2, {
        let special_path = arceos_posix_api::handle_file_path(AT_FDCWD, Some(special.get()?), true)
            .inspect_err(|err| log::error!("umount2: special: {:?}", err))?;

        if flags != 0 {
            debug!("flags unimplemented");
            return Err(axerrno::LinuxError::EPERM);
        }

        // 检查挂载点路径是否存在
        if !special_path.exists() {
            debug!("mount path not exist");
            return Err(axerrno::LinuxError::EPERM);
        }
        // 从挂载点中删除
        if !umount_fat_fs(&special_path) {
            debug!("umount error");
            return Err(axerrno::LinuxError::EPERM);
        }


        Ok(0) 
    })
    
}

pub struct MountedFs {
    //pub inner: Arc<Mutex<FATFileSystem>>,
    pub device: FilePath,
    pub mnt_dir: FilePath,
}

impl MountedFs {
    pub fn new(device: &FilePath, mnt_dir: &FilePath) -> Self {
        assert!(
            device.is_file() && mnt_dir.is_dir(),
            "device must be a file and mnt_dir must be a dir"
        );
        Self {
            device: device.clone(),
            mnt_dir: mnt_dir.clone(),
        }
    }
    #[allow(unused)]
    pub fn device(&self) -> FilePath {
        self.device.clone()
    }

    pub fn mnt_dir(&self) -> FilePath {
        self.mnt_dir.clone()
    }
}

static MOUNTED: Mutex<Vec<MountedFs>> = Mutex::new(Vec::new());

pub fn mount_fat_fs(device_path: &FilePath, mount_path: &FilePath) -> bool {
    if mount_path.exists() {
        MOUNTED.lock().push(MountedFs::new(device_path, mount_path));
        info!("mounted {} to {}", device_path.as_str(), mount_path.as_str());
        return true;
    }
    
    info!(
        "mount failed: {} to {}",
        device_path.as_str(),
        mount_path.as_str()
    );
    false
}

pub fn umount_fat_fs(mount_path: &FilePath) -> bool {
    let mut mounted = MOUNTED.lock();
    let mut i = 0;
    while i < mounted.len() {
        if mounted[i].mnt_dir() == *mount_path  {
            mounted.remove(i);
            info!("umounted {}", mount_path.as_str());
            return true;
        }
        i += 1;
    }
    info!("umount failed: {}", mount_path.as_str());
    false
}


pub fn check_mounted(path: &FilePath) -> bool {
    let mounted = MOUNTED.lock();
    for m in mounted.iter() {
        if path.starts_with(&m.mnt_dir()) {
            debug!("{} is mounted", path.as_str());
            return true;
        }
    }
    false
}

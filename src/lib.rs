extern crate argon2rs;
extern crate rand;
extern crate extra;
extern crate syscall;
#[macro_use] extern crate failure;

use std::convert::From;
use std::fs::{File, OpenOptions, rename};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use argon2rs::verifier::Encoded;
use argon2rs::{Argon2, Variant};
use failure::Error;
use syscall::Error as SyscallError;
use syscall::flag::O_EXCL;
use rand::os::OsRng;
use rand::Rng;

//TODO: Allow a configuration file for all this someplace
const PASSWD_FILE: &'static str = "/etc/passwd";
const GROUP_FILE: &'static str = "/etc/group";
const MIN_GID: usize = 1000;
const MAX_GID: usize = 6000;
const MIN_UID: usize = 1000;
const MAX_UID: usize = 6000;

pub type Result<T> = std::result::Result<T , Error>;

/// Errors that might happen while using this crate
#[derive(Debug, Fail, PartialEq)]
pub enum UsersError {
    #[fail(display = "os error: code {}", reason)]
    Os { reason: String },
    #[fail(display = "parse error: {}", reason)]
    Parsing { reason: String },
    #[fail(display = "user/group not found")]
    NotFound,
    #[fail(display = "user/group already exists")]
    AlreadyExists,
}

fn parse_error(reason: &str) -> UsersError {
    UsersError::Parsing { reason: reason.into() }
}

fn os_error(reason: &str) -> UsersError {
    UsersError::Os { reason: reason.into() }
}

impl From<SyscallError> for UsersError {
    fn from(syscall_error: SyscallError) -> UsersError {
        UsersError::Os { reason: format!("{}", syscall_error) }
    }
}

/// A struct representing a Redox user.
/// Currently maps to an entry in the '/etc/passwd' file.
pub struct User {
    /// Username (login name)
    pub user: String,
    /// Hashed password
    hash: String,
    /// Argon2 Hashing session, stored to simplify API
    encoded: Encoded,
    /// User id
    pub uid: usize,
    /// Group id
    pub gid: usize,
    /// Real name (GECOS field)
    pub name: String,
    /// Home directory path
    pub home: String,
    /// Shell path
    pub shell: String
}

impl User {
    //Parse a single entry from /etc/passwd
    pub(crate) fn parse(line: &str) -> Result<User> {
        let mut parts = line.split(';');

        let user = parts.next().ok_or(parse_error("expected user"))?;
        let hash = parts.next().ok_or(parse_error("expected hash"))?;
        let uid = parts.next().ok_or(parse_error("expected uid"))?.parse::<usize>()?;
        let gid = parts.next().ok_or(parse_error("expected uid"))?.parse::<usize>()?;
        let name = parts.next().ok_or(parse_error("expected real name"))?;
        let home = parts.next().ok_or(parse_error("expected home directory path"))?;
        let shell = parts.next().ok_or(parse_error("expected shell path"))?;

        Ok(User {
            user: user.into(),
            hash: hash.into(),
            encoded: Encoded::from_u8(hash.as_bytes())?,
            uid: uid,
            gid: gid,
            name: name.into(),
            home: home.into(),
            shell: shell.into()
        })
    }
    
    /// Set the password for a user. Make sure the password you have
    /// received is actually what the user wants as their password.
    pub fn set_passwd(&mut self, password: &str) -> Result<()> {
        let a2 = Argon2::new(10, 1, 4096, Variant::Argon2i)?;
        let salt = format!("{:X}", OsRng::new()?.next_u64());
        
        self.encoded = Encoded::new(a2, password.as_bytes(), salt.as_bytes(), &[], &[]);
        self.hash = String::from_utf8(self.encoded.to_u8())?;
        Ok(())
    }
    
    /// Verify the password. If the hash is empty, we override Argon's
    /// default behavior and only allow login if the password field is
    /// also empty.
    pub fn verify_passwd(&self, password: &str) -> bool {
        if self.hash != "" {
            self.encoded.verify(password.as_bytes())
        } else if password == "" {
            true
        } else {
            false
        }
    }
    
    /// Determine if the password is unset
    pub fn passwd_unset(&self) -> bool {
        self.hash == ""
    }
    
    /// Get a Command to run the user's default shell
    pub fn shell_cmd(&self) -> Command {
        self.login_cmd(&self.user)
    }
    
    /// Provide a login command for the user, which is any
    /// entry point for starting a user's session, whether
    /// a shell (use [`shell_cmd`](struct.User.html#method.shell_cmd) instead) or a graphical init.
    pub fn login_cmd(&self, cmd: &String) -> Command {
        let mut command = Command::new(cmd);
        command.uid(self.uid as u32)
            .gid(self.gid as u32)
            .current_dir(&self.home)
            .env("USER", &self.user)
            .env("UID", format!("{}", self.uid))
            .env("GROUPS", format!("{}", self.gid))
            .env("HOME", &self.home)
            .env("SHELL", &self.shell);
        command
    }
}

impl ToString for User {
    fn to_string(&self) -> String {
        format!("{};{};{};{};{};{};{}", self.user, self.hash, self.uid, self.gid, self.name, self.home, self.shell)
    }
}

/// A struct representing a Redox users group.
/// Currently maps to an '/etc/group' file entry.
pub struct Group {
    /// Group name
    pub group: String,
    /// Unique group id
    pub gid: usize,
    /// Group members usernames
    pub users: Vec<String>,
}

impl Group {
    //Parse a single entry from /etc/group
    pub(crate) fn parse(line: &str) -> Result<Group> {
        let mut parts = line.split(';');

        let group = parts.next().ok_or(parse_error("expected group"))?;
        let gid = parts.next().ok_or(parse_error("expected gid"))?.parse::<usize>()?;
        //Allow for an empty users field. If there is a better way to do this, do it
        let users_str = parts.next().unwrap_or(" ");
        let users = users_str.split(',').map(|u| u.into()).collect();

        Ok(Group {
            group: group.into(),
            gid: gid,
            users: users
        })
    }
}

impl ToString for Group {
    fn to_string(&self) -> String {
        format!("{};{};{}", self.group, self.gid, self.users.join(","))
    }
}

/// Gets the current process effective user ID.
///
/// This function issues the `geteuid` system call returning the process effective
/// user id.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let euid = get_euid().unwrap();
///
/// ```
pub fn get_euid() -> Result<usize> {
    match syscall::geteuid() {
        Ok(euid) => Ok(euid),
        Err(syscall_error) => Err(From::from(os_error(syscall_error.text())))
    }
}

/// Gets the current process real user ID.
///
/// This function issues the `getuid` system call returning the process real
/// user id.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let uid = get_uid().unwrap();
///
/// ```
pub fn get_uid() -> Result<usize> {
    match syscall::getuid() {
        Ok(uid) => Ok(uid),
        Err(syscall_error) => Err(From::from(os_error(syscall_error.text())))
    }
}

/// Gets the current process effective group ID.
///
/// This function issues the `getegid` system call returning the process effective
/// group id.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let egid = get_egid().unwrap();
///
/// ```
pub fn get_egid() -> Result<usize> {
    match syscall::getegid() {
        Ok(egid) => Ok(egid),
        Err(syscall_error) => Err(From::from(os_error(syscall_error.text())))
    }
}

/// Gets the current process real group ID.
///
/// This function issues the `getegid` system call returning the process real
/// group id.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let gid = get_gid().unwrap();
///
/// ```
pub fn get_gid() -> Result<usize> {
    match syscall::getgid() {
        Ok(gid) => Ok(gid),
        Err(syscall_error) => Err(From::from(os_error(syscall_error.text())))
    }
}

/// Struct encapsulating all users on the system
///
/// [`AllUsers`](struct.AllUsers.html) is a struct providing
/// (borrowed) access to all the users and groups on the system.
pub struct AllUsers {
    users: Vec<User>
    
}

impl AllUsers {
    //TODO: Need to somehow return a valid AllUsers, but still indicate if a line failed
    pub fn new() -> Result<AllUsers> {
        let mut file_data = String::new();
        let mut file = File::open(PASSWD_FILE)?;
        file.read_to_string(&mut file_data)?;
        
        let mut entries: Vec<User> = Vec::new();
        
        for line in file_data.lines() {
            if let Ok(user) = User::parse(line) {
                entries.push(user);
            }
        }
        
        Ok(AllUsers { users: entries })
    }
    
    /// Syncs the data stored in the AllUsers instance to the filesystem.
    /// To apply changes to the system from an AllUsers, you MUST call this function!
    // Not a part of the API
    fn write(&self) -> Result<()> {
        let mut userstring = String::new();
        for user in &self.users {
            userstring.push_str(&format!("{}\n", user.to_string().as_str()));
        }
        let lockfile_name = format!("{}.lock", PASSWD_FILE);
        let mut options = OpenOptions::new();
        options.truncate(true)
            .write(true)
            .create(true)
            .custom_flags(O_EXCL as i32);
        let mut file = options.open(&lockfile_name)?;
        file.write(userstring.as_bytes())?;
        rename(lockfile_name, PASSWD_FILE)?;
        Ok(())
    }
    
    /// Borrow the [`User`](struct.User.html) representing a user for a given username.
    ///
    /// This function will read the users database (currently '/etc/passwd')
    /// returning a [`User`](struct.User.html) struct representing the user
    /// who's username matches and [`UsersError::NotFound`](enum.UserError.html#variant.NotFound)
    /// otherwise.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let user = users.get_user_by_id(1).unwrap();
    /// ```
    pub fn get_by_name<T: AsRef<str>>(&self, username: T) -> Result<&User> {
        self.users.iter()
            .find(|user| user.user == username.as_ref())
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of ['get_by_name'](struct.AllUsers.html#method.get_by_name)
    pub fn get_mut_by_name<T: AsRef<str>>(&mut self, username: T) -> Result<&mut User> {
        self.users.iter_mut()
            .find(|user| user.user == username.as_ref())
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Borrow the [`User`](struct.AllUsers.html) representing given user ID.
    ///
    /// This function will read the users database (currently '/etc/passwd')
    /// returning a [`User`](struct.User.html) struct representing the
    /// user who's UID matches and [`UsersError::NotFound`](enum.UserError.html#variant.NotFound)
    /// otherwise.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let user = users.get_user_by_id(1).unwrap();
    /// ```
    pub fn get_by_id(&self, uid: usize) -> Result<&User> {
        self.users.iter()
            .find(|user| user.uid == uid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of [`get_by_id`](struct.AllUsers.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, uid: usize) -> Result<&mut User> {
        self.users.iter_mut()
            .find(|user| user.uid == uid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Provides an unused user id, defined as "unused" by the system
    /// defaults, between 1000 and 6000
    ///
    /// # Examples
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let uid = users.get_unique_user_id().expect("no available uid");
    /// ```
    //TODO: Allow for a MIN_UID and MAX_UID config file someplace
    pub fn get_unique_id(&self) -> Option<usize> {
        for uid in MIN_UID..MAX_UID {
            let mut used = false;
            for user in self.users.iter() {
                if uid == user.gid {
                    used = true;
                    continue;
                }
            }
            if used == false {
                return Some(uid);
            }
        }
        None
    }
    
    /// Adds a user with the specified attributes to the
    /// users database (currently `/etc/passwd`). Note that the
    /// user's password is set empty during this call.
    ///
    /// Returns Result with error information if the operation was not successful
    pub fn add_user(&mut self, login: &str, uid: usize, gid: usize, name: &str, home: &str, shell: &str) -> Result<()> {
        for user in self.users.iter() {
            if user.user == login || user.uid == uid {
                return Err(From::from(UsersError::AlreadyExists))
            }
        }
        
        self.users.push(User{
            user: login.into(),
            hash: "".into(),
            encoded: Encoded::from_u8("".as_bytes())?,
            uid: uid,
            gid: gid,
            name: name.into(),
            home: home.into(),
            shell: shell.into()
        });

        Ok(())
    }
}

//TODO: Do this in a way that propagates errors to application
impl Drop for AllUsers {
    fn drop(&mut self) {
        self.write();
    }
}

/// Struct encapsulating all the groups on the system
///
/// [`AllGroups`](struct.AllGroups.html) is a struct that provides
/// (borrowed) access to all groups on the system.
pub struct AllGroups {
    groups: Vec<Group>
}

impl AllGroups {
    ///TODO: Indicate if parsing an individual line failed or not
    pub fn new() -> Result<AllGroups> {
        let mut file_data = String::new();
        let mut file = File::open(GROUP_FILE)?;
        file.read_to_string(&mut file_data)?;
        
        let mut entries: Vec<Group> = Vec::new();
        
        for line in file_data.lines() {
            if let Ok(group) = Group::parse(line) {
                entries.push(group);
            }
        }
        
        Ok(AllGroups{ groups: entries })
    }
    
    /// Syncs the data stored in the AllGroups instance to the filesystem.
    /// To apply changes to the AllGroups, you MUST call this function.
    /// This is NOT a part of the redox_users API
    fn write(&self) -> Result<()> {
        let mut groupstring = String::new();
        for group in &self.groups {
            groupstring.push_str(&format!("{}\n", group.to_string().as_str()));
        }
        let lockfile_name = format!("{}.lock", GROUP_FILE);
        let mut options = OpenOptions::new();
        options.truncate(true)
            .write(true)
            .create(true)
            .custom_flags(O_EXCL as i32);
        let mut file = options.open(&lockfile_name)?;
        file.write(groupstring.as_bytes())?;
        rename(lockfile_name, GROUP_FILE)?;
        Ok(())
    }
    
    /// Gets the [`Group`](struct.Group.html) for a given group name.
    ///
    /// This function returns a [`Group`](struct.AllGroups.html) struct representing the group
    /// with a matching name and [`UsersError::NotFound`](enum.UsersError.html#variant.NotFound)
    /// otherwise.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let group = groups.get_group_by_name("wheel").unwrap();
    /// ```
    pub fn get_by_name<T: AsRef<str>>(&self, groupname: T) -> Result<&Group> {
        self.groups.iter()
            .find(|group| group.group == groupname.as_ref())
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of [`get_by_name`](struct.AllGroups.html#method.get_by_name)
    pub fn get_mut_by_name<T: AsRef<str>>(&mut self, groupname: T) -> Result<&mut Group> {
        self.groups.iter_mut()
            .find(|group| group.group == groupname.as_ref())
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Gets the [`Group`](struct.Group.html) for a given group ID.
    ///
    /// This function will return a [`Group`](struct.Group.html) struct representing the group
    /// with a matching ID and and [`UsersError::NotFound`](enum.UsersError.html#variant.NotFound)
    /// otherwise.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let group = groups.get_group_by_id(1).unwrap();
    /// ```
    pub fn get_by_id(&self, gid: usize) -> Result<&Group> {
        self.groups.iter()
            .find(|group| group.gid == gid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of [`get_by_id`](struct.AllGroups.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, gid: usize) -> Result<&mut Group> {
        self.groups.iter_mut()
            .find(|group| group.gid == gid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Provides an unused group id, defined as "unused" by the system
    /// defaults, between 1000 and 6000
    ///
    /// # Examples
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let gid = groups.get_unique_group_id().expect("no available gid");
    /// ```
    //TODO: Allow for a MIN_GID and MAX_GID config file someplace
    pub fn get_unique_id(&self) -> Option<usize> {
        for gid in MIN_GID..MAX_GID {
            let mut used = false;
            for group in self.groups.iter() {
                if gid == group.gid {
                    used = true;
                    continue;
                }
            }
            if used == false {
                return Some(gid);
            }
        }

        None
    }
    
    /// Adds a group with the specified attributes to this AllGroups
    ///
    /// Returns Result with error information if the operation was not successful
    ///
    /// Note that calls to this function DO NOT apply changes to the system.
    /// [`write`](struct.AllGroups.html#method.write) must be called for changes to take effect.
    //UNOPTIMIZED: Currently requiring two iterations (if the user calls get_unique_group_id):
    //  one: for determine if the group already exists
    //  two: if the user calls get_unique_group_id, which iterates over the same iterator
    pub fn add_group(&mut self, name: &str, gid: usize, users: &[&str]) -> Result<()> {
        for group in self.groups.iter() {
            if group.group == name || group.gid == gid {
                return Err(From::from(UsersError::AlreadyExists))
            }
        }
        
        self.groups.push(Group {
            group: name.into(),
            gid: gid,
            users: users.iter().map(|user| user.to_string()).collect()
            //Might be cleaner... Also breaks...
            //users: users.iter().map(String::to_string).collect()
        });
        
        Ok(())
    }
}

//TODO: Do this in a way that propagates errors to application
impl Drop for AllGroups {
    fn drop(&mut self) {
        self.write();
    }
}

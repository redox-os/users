extern crate argon2rs;
extern crate extra;
extern crate syscall;
#[macro_use] extern crate failure;

use std::convert::From;
use std::fs::{File, rename};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::vec::IntoIter;

use argon2rs::verifier::Encoded;
use argon2rs::{Argon2, Variant};
use failure::Error;
use syscall::Error as SyscallError;

const PASSWD_FILE: &'static str = "/etc/passwd";
const GROUP_FILE: &'static str = "/etc/group";
const MIN_GID: u32 = 1000;
const MAX_GID: u32 = 6000;
const MIN_UID: u32 = 1000;
const MAX_UID: u32 = 6000;

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
#[derive(Clone, Debug)]
pub struct User {
    /// Username (login name)
    pub user: String,
    /// Hashed password
    hash: String,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
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
        let uid = parts.next().ok_or(parse_error("expected uid"))?.parse::<u32>()?;
        let gid = parts.next().ok_or(parse_error("expected uid"))?.parse::<u32>()?;
        let name = parts.next().ok_or(parse_error("expected real name"))?;
        let home = parts.next().ok_or(parse_error("expected home directory path"))?;
        let shell = parts.next().ok_or(parse_error("expected shell path"))?;

        Ok(User {
            user: user.into(),
            hash: hash.into(),
            uid: uid,
            gid: gid,
            name: name.into(),
            home: home.into(),
            shell: shell.into()
        })
    }

    pub(crate) fn parse_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<User>> {
        let mut file_data = String::new();
        let mut file = File::open(file_path)?;
        file.read_to_string(&mut file_data)?;

        let mut entries: Vec<User> = Vec::new();

        for line in file_data.lines() {
            if let Ok(user) = User::parse(line) {
                entries.push(user);
            }
        }

        Ok(entries)
    }
    
    /// Set the password for a user.
    /// TODO: Do not require salt (get an unused one from someplace...)
    pub fn set_passwd(&mut self, password: &str, salt: &str) -> Result<()> {
        let a2 = Argon2::new(10, 1, 4096, Variant::Argon2i)?;
        let e = Encoded::new(a2, password.as_bytes(), salt.as_bytes(), &[], &[]);
        self.hash = String::from_utf8(e.to_u8())?;
        Ok(())
    }
    
    /// Verify the password. If the hash is empty, we override Argon's
    /// default behavior and only allow login if the password field is
    /// also empty.
    pub fn verify_passwd(&self, password: &str) -> Result<bool> {
        if self.hash != "" {
            let e = Encoded::from_u8(self.hash.as_bytes())?;
            Ok(e.verify(password.as_bytes()))
        } else if password == "" {
            Ok(true)
        } else {
            Ok(false)
        }
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
        command.uid(self.uid)
            .gid(self.gid)
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
#[derive(Clone, Debug)]
pub struct Group {
    /// Group name
    pub group: String,
    /// Unique group id
    pub gid: u32,
    /// Group members usernames
    pub users: Vec<String>,
}

impl Group {
    //Parse a single entry from /etc/group
    pub(crate) fn parse(line: &str) -> Result<Group> {
        let mut parts = line.split(';');

        let group = parts.next().ok_or(parse_error("expected group"))?;
        let gid = parts.next().ok_or(parse_error("expected gid"))?.parse::<u32>()?;
        //Allow for an empty users field. If there is a better way to do this, do it
        let users_str = parts.next().unwrap_or(" ");
        let users = users_str.split(',').map(|u| u.into()).collect();

        Ok(Group {
            group: group.into(),
            gid: gid,
            users: users
        })
    }

    pub(crate) fn parse_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<Group>> {
        let mut file_data = String::new();
        let mut file = File::open(file_path)?;
        file.read_to_string(&mut file_data)?;

        let mut entries: Vec<Group> = Vec::new();

        for line in file_data.lines() {
            if let Ok(group) = Group::parse(line) {
                entries.push(group);
            }
        }

        Ok(entries)
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
    //TODO: Convert this Method to return Result<AllUsers>
    pub fn new() -> Result<AllUsers> {
        let users = User::parse_file(PASSWD_FILE)?;

        Ok(AllUsers { users })
    }
    
    /// Syncs the data stored in the AllUsers instance to the filesystem.
    /// To apply changes to the system from an AllUsers, you MUST call this function!
    /// This is NOT a part of the redox_users API
    fn write(&self) -> Result<()> {
        let mut userstring = String::new();
        for user in &self.users {
            userstring.push_str(&format!("{}\n", user.to_string().as_str()));
        }
        let tempfile = format!("{}.lock", PASSWD_FILE);
        let mut file = File::create(&tempfile)?;
        file.write(userstring.as_bytes())?;
        rename(tempfile, PASSWD_FILE);
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
            .find(|user| user.uid as usize == uid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of [`get_by_id`](struct.AllUsers.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, uid: usize) -> Result<&mut User> {
        self.users.iter_mut()
            .find(|user| user.uid as usize == uid)
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
    pub fn get_unique_user_id(&self) -> Option<u32> {
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
    pub fn add_user(&mut self, login: &str, uid: u32, gid: u32, name: &str, home: &str, shell: &str) -> Result<()> {
        for user in self.users.iter() {
            if user.user == login || user.uid == uid {
                return Err(From::from(UsersError::AlreadyExists))
            }
        }
        
        self.users.push(User{
            user: login.into(),
            hash: "".into(),
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

/* Not sure if This needs to be an iterator...
impl Iterator for AllUsers {
    type Item = User;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}*/

/// Struct encapsulating all the groups on the system
///
/// [`AllGroups`](struct.AllGroups.html) is a struct that provides
/// (borrowed) access to all groups on the system.
pub struct AllGroups {
    groups: Vec<Group>
    //iter: IntoIter<Group>
}

impl AllGroups {
    /// Create a new AllGroups, parsing the group file.
    pub fn new() -> Result<AllGroups> {
        let groups = Group::parse_file(GROUP_FILE)?;
        
        Ok(AllGroups{ groups })
    }
    
    /// Syncs the data stored in the AllGroups instance to the filesystem.
    /// To apply changes to the AllGroups, you MUST call this function.
    /// This is NOT a part of the redox_users API
    fn write(&self) -> Result<()> {
        let mut groupstring = String::new();
        for group in &self.groups {
            groupstring.push_str(&format!("{}\n", group.to_string().as_str()));
        }
        let tempfile = format!("{}.lock", GROUP_FILE);
        let mut file = File::create(&tempfile)?;
        file.write(groupstring.as_bytes())?;
        rename(tempfile, GROUP_FILE);
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
    pub fn get_by_id(&self, gid: u32) -> Result<&Group> {
        self.groups.iter()
            .find(|group| group.gid == gid)
            .ok_or(From::from(UsersError::NotFound))
    }
    
    /// Mutable version of [`get_by_id`](struct.AllGroups.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, gid: u32) -> Result<&mut Group> {
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
    pub fn get_unique_group_id(&self) -> Option<u32> {
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
    pub fn add_group(&mut self, name: &str, gid: u32, users: &[&str]) -> Result<()> {
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

/*
impl Iterator for AllGroups {
    type Item = Group;
    
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}*/

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
    encoded: Option<Encoded>,
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
        
        let encoded = match hash {
            "" => None,
            _ => Some(Encoded::from_u8(hash.as_bytes())?)
        };
        
        Ok(User {
            user: user.into(),
            hash: hash.into(),
            encoded: encoded,
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
        let encoded = Encoded::new(a2, password.as_bytes(), salt.as_bytes(), &[], &[]);
        
        self.hash = String::from_utf8(encoded.to_u8())?;
        self.encoded = Some(encoded);
        Ok(())
    }
    
    /// Verify the password. If the hash is empty, we override Argon's
    /// default behavior and only allow login if the password field is
    /// also empty.
    pub fn verify_passwd(&self, password: &str) -> bool {
        if let Some(ref encoded) = self.encoded {
            encoded.verify(password.as_bytes())
        } else if self.hash == "" {
            true
        } else {
            false
        }
    }
    
    /// Determine if the hash for the password is blank
    /// (Any user can log in as this user with no password).
    pub fn is_passwd_blank(&self) -> bool {
        self.hash == ""
    }
    
    /// Determine if the hash for the password is unset
    /// (No users can log in as this user, aka, must use sudo or su)
    pub fn is_passwd_unset(&self) -> bool {
        //TODO: Implement this...
        false
    }
    
    /// Get a Command to run the user's default shell
    /// (See [`login_cmd`](struct.User.html#method.login_cmd) for more doc)
    pub fn shell_cmd(&self) -> Command {
        self.login_cmd(&self.shell)
    }
    
    /// Provide a login command for the user, which is any
    /// entry point for starting a user's session, whether
    /// a shell (use [`shell_cmd`](struct.User.html#method.shell_cmd) instead) or a graphical init.
    ///
    /// The `Command` will have set the users UID and GID, its CWD will be
    /// set to the users's home directory and the follwing enviroment variables will
    /// be populated like so:
    ///
    ///    - `USER` set to the user's `user` field.
    ///    - `UID` set to the user's `uid` field.
    ///    - `GROUPS` set the user's `gid` field.
    ///    - `HOME` set to the user's `home` field.
    ///    - `SHELL` set to the user's `shell` field.
    pub fn login_cmd<T: AsRef<str>>(&self, cmd: T) -> Command where
        T: std::convert::AsRef<std::ffi::OsStr>
    {
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
///
/// ## Notes
/// Note that everything in this section also applies to
/// [`AllGroups`](struct.AllGroups.html)
///
/// * If you mutate anything in conjunction with an AllUsers,
///   you must call the [`save`](struct.AllUsers.html#method.save)
///   method in order for those changes to be applied to the system.
/// * The API here is kept small on purpose in order to reduce the
///   surface area for security exploitation. Most mutating actions
///   can be accomplished via the [`get_mut_by_id`](struct.AllUsers.html#method.get_mut_by_id)
///   and [`get_mut_by_name`](struct.AllUsers.html#method.get_mut_by_name)
///   functions.
pub struct AllUsers {
    users: Vec<User>
    
}

impl AllUsers {
    /// Create a new AllUsers
    //TODO: Indicate if parsing an individual line failed or not
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
    
    /// Borrow the [`User`](struct.User.html) representing a user for a given username.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let user = users.get_user_by_id(1).unwrap();
    /// ```
    pub fn get_by_name<T: AsRef<str>>(&self, username: T) -> Option<&User> {
        self.users.iter()
            .find(|user| user.user == username.as_ref())
    }
    
    /// Mutable version of ['get_by_name'](struct.AllUsers.html#method.get_by_name)
    pub fn get_mut_by_name<T: AsRef<str>>(&mut self, username: T) -> Option<&mut User> {
        self.users.iter_mut()
            .find(|user| user.user == username.as_ref())
    }
    
    /// Borrow the [`User`](struct.AllUsers.html) representing given user ID.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let user = users.get_user_by_id(1).unwrap();
    /// ```
    pub fn get_by_id(&self, uid: usize) -> Option<&User> {
        self.users.iter()
            .find(|user| user.uid == uid)
    }
    
    /// Mutable version of [`get_by_id`](struct.AllUsers.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, uid: usize) -> Option<&mut User> {
        self.users.iter_mut()
            .find(|user| user.uid == uid)
    }
    
    /// Provides an unused user id, defined as "unused" by the system
    /// defaults, between 1000 and 6000
    ///
    /// # Examples
    /// ```
    /// let users = AllUsers::new().unwrap();
    /// let uid = users.get_unique_user_id().expect("no available uid");
    /// ```
    pub fn get_unique_id(&self) -> Option<usize> {
        for uid in MIN_UID..MAX_UID {
            if !self.users.iter().any(|user| uid == user.uid) {
                return Some(uid);
            }
        }
        None
    }
    
    /// Adds a user with the specified attributes to the
    /// AllUsers instance. Note that the
    /// user's password is set empty during this call.
    ///
    /// This function is classified as a mutating operation,
    /// and users must therefore call [`save`](struct.AllUsers.html#method.save)
    /// in order for the new user to be applied to the system.
    pub fn add_user(&mut self, login: &str, uid: usize, gid: usize, name: &str, home: &str, shell: &str) -> Result<()> {
        if self.users.iter().any(|user| user.user == login || user.uid == uid) {
            return Err(From::from(UsersError::AlreadyExists))
        }
        
        self.users.push(User{
            user: login.into(),
            hash: "".into(),
            encoded: None,
            uid: uid,
            gid: gid,
            name: name.into(),
            home: home.into(),
            shell: shell.into()
        });
        Ok(())
    }
    
    /// Remove a user from the system. This is a mutating operation,
    /// and users of the crate must therefore call [`save`](struct.AllUsers.html#method.save)
    /// in order for changes to be applied to the system.
    pub fn remove_by_name(&mut self, name: String) -> Result<()> {
        self.remove(|user| user.user == name )
    }
    
    /// User-id version of [`remove_by_name`](struct.AllUsers.html#method.remove_by_name)
    pub fn remove_by_id(&mut self, id: usize) -> Result<()> {
        self.remove(|user| user.uid == id )
    }
    
    // Reduce code duplication
    fn remove<P>(&mut self, predicate: P) -> Result<()> where
        P: FnMut(&User) -> bool
    {
        let pos;
        {
            let mut iter = self.users.iter();
            if let Some(posi) = iter.position(predicate) {
                pos = posi;
            } else {
                return Err(From::from(UsersError::NotFound));
            };
        }
        self.users.remove(pos);
        Ok(())
    }
    
    /// Syncs the data stored in the AllUsers instance to the filesystem.
    /// To apply changes to the system from an AllUsers, you MUST call this function!
    /// This function currently does a bunch of fs I/O so it is error-prone.
    pub fn save(&self) -> Result<()> {
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
}

/// Struct encapsulating all the groups on the system
///
/// [`AllGroups`](struct.AllGroups.html) is a struct that provides
/// (borrowed) access to all groups on the system.
///
/// General notes that also apply to this struct may be found with
/// [`AllUsers`](struct.AllUsers.html).
pub struct AllGroups {
    groups: Vec<Group>
}

//UNOPTIMIZED: Right now this struct is just a Vec and we are doing O(n)
// operations over the vec to do the `get` methods. A multi-key
// hashmap would be a godsend here for performance.
impl AllGroups {
    /// Create a new AllGroups
    //TODO: Indicate if parsing an individual line failed or not
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
    
    /// Gets the [`Group`](struct.Group.html) for a given group name.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let group = groups.get_group_by_name("wheel").unwrap();
    /// ```
    pub fn get_by_name<T: AsRef<str>>(&self, groupname: T) -> Option<&Group> {
        self.groups.iter()
            .find(|group| group.group == groupname.as_ref())
    }
    
    /// Mutable version of [`get_by_name`](struct.AllGroups.html#method.get_by_name)
    pub fn get_mut_by_name<T: AsRef<str>>(&mut self, groupname: T) -> Option<&mut Group> {
        self.groups.iter_mut()
            .find(|group| group.group == groupname.as_ref())
    }
    
    /// Gets the [`Group`](struct.Group.html) for a given group ID.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let group = groups.get_group_by_id(1).unwrap();
    /// ```
    pub fn get_by_id(&self, gid: usize) -> Option<&Group> {
        self.groups.iter()
            .find(|group| group.gid == gid)
    }
    
    /// Mutable version of [`get_by_id`](struct.AllGroups.html#method.get_by_id)
    pub fn get_mut_by_id(&mut self, gid: usize) -> Option<&mut Group> {
        self.groups.iter_mut()
            .find(|group| group.gid == gid)
    }
    
    /// Provides an unused group id, defined as "unused" by the system
    /// defaults, between 1000 and 6000
    ///
    /// # Examples
    /// ```
    /// let groups = AllGroups::new().unwrap();
    /// let gid = groups.get_unique_group_id().expect("no available gid");
    /// ```
    pub fn get_unique_id(&self) -> Option<usize> {
        for gid in MIN_GID..MAX_GID {
            if !self.groups.iter().any(|group| gid == group.gid) {
                return Some(gid);
            }
        }
        None
    }
    
    /// Adds a group with the specified attributes to this AllGroups
    ///
    /// This function is classified as a mutating operation,
    /// and users must therefore call [`save`](struct.AllUsers.html#method.save)
    /// in order for the new group to be applied to the system.
    pub fn add_group(&mut self, name: &str, gid: usize, users: &[&str]) -> Result<()> {
        if self.groups.iter().any(|group| group.group == name || group.gid == gid) {
            return Err(From::from(UsersError::AlreadyExists))
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
    
    /// Remove a group from the system. This is a mutating operation,
    /// and users of the crate must therefore call [`save`](struct.AllGroups.html#method.save)
    /// in order for changes to be applied to the system.
    pub fn remove_by_name(&mut self, name: String) -> Result<()> {
        self.remove(|group| group.group == name )
    }
    
    /// Group-id version of [`remove_by_name`](struct.AllGroups.html#method.remove_by_name)
    pub fn remove_by_id(&mut self, id: usize) -> Result<()> {
        self.remove(|group| group.gid == id )
    }
    
    // Reduce code duplication
    fn remove<P>(&mut self, predicate: P) -> Result<()> where
        P: FnMut(&Group) -> bool
    {
        let pos;
        {
            let mut iter = self.groups.iter();
            if let Some(posi) = iter.position(predicate) {
                pos = posi;
            } else {
                return Err(From::from(UsersError::NotFound));
            };
        }
        self.groups.remove(pos);
        Ok(())
    }
    
    /// Syncs the data stored in the AllGroups instance to the filesystem.
    /// To apply changes to the AllGroups, you MUST call this function.
    /// This function currently does a lot of fs I/O so it is error-prone.
    pub fn save(&self) -> Result<()> {
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
}

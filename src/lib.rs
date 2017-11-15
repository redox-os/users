extern crate argon2rs;
extern crate extra;
extern crate syscall;

use std::io::{self, Read};
use std::fs::File;
use std::process::exit;
use std::path::Path;

use argon2rs::verifier::Encoded;
use argon2rs::{Argon2, Variant};
use extra::option::OptionalExt;

const PASSWD_FILE: &'static str = "/etc/passwd";
const GROUP_FILE: &'static str = "/etc/group";

/// A struct representing a Redox user.
/// Currently maps to an entry in the '/etc/passwd' file.
#[derive(Clone, Debug)]
pub struct User {
    /// Username
    pub user: String,
    /// Hashed password
    pub hash: String,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Real name
    pub name: String,
    /// Home directory path
    pub home: String,
    /// Shell path
    pub shell: String
}

impl User {
    pub fn parse(line: &str) -> Result<User, ()> {
        let mut parts = line.split(';');

        let user = parts.next().ok_or(())?;
        let hash = parts.next().ok_or(())?;
        let uid = parts.next().ok_or(())?.parse::<u32>().or(Err(()))?;
        let gid = parts.next().ok_or(())?.parse::<u32>().or(Err(()))?;
        let name = parts.next().ok_or(())?;
        let home = parts.next().ok_or(())?;
        let shell = parts.next().ok_or(())?;

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

    pub(crate) fn parse_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<User>, ()> {

        let mut stderr = io::stderr();

        let mut file_data = String::new();
        let mut file = File::open(file_path).try(&mut stderr);
        file.read_to_string(&mut file_data).try(&mut stderr);

        let mut entries: Vec<User> = Vec::new();

        for line in file_data.lines() {
            if let Ok(user) = User::parse(line) {
                entries.push(user);
            }
        }

        Ok(entries)
    }

    pub fn encode_passwd(password: &str, salt: &str) -> String {
        let a2 = Argon2::new(10, 1, 4096, Variant::Argon2i).unwrap();
        let e = Encoded::new(a2, password.as_bytes(), salt.as_bytes(), &[], &[]);
        String::from_utf8(e.to_u8()).unwrap()
    }

    pub fn verify_passwd(&self, password: &str) -> bool {
        let e = Encoded::from_u8(self.hash.as_bytes()).unwrap();
        e.verify(password.as_bytes())
    }
}

/// A struct representing a Redox users group.
/// Currently maps to an '/etc/group' file entry.
#[derive(Clone, Debug)]
pub struct Group {
    /// Group name
    pub group: String,
    // Unique group id
    pub gid: u32,
    // Group members usernames
    pub users: Vec<String>,
}

impl Group {
    pub fn parse(line: &str) -> Result<Group, ()> {
        let mut parts = line.split(';');

        let group = parts.next().ok_or(())?;
        let gid = parts.next().ok_or(())?.parse::<u32>().or(Err(()))?;
        let users_str = parts.next().ok_or(())?;
        let users = users_str.split(',').map(|u| u.into()).collect();

        Ok(Group {
            group: group.into(),
            gid: gid,
            users: users
        })
    }

    pub(crate) fn parse_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<Group>, ()> {
        let mut stderr = io::stderr();

        let mut file_data = String::new();
        let mut file = File::open(file_path).try(&mut stderr);
        file.read_to_string(&mut file_data).try(&mut stderr);

        let mut entries: Vec<Group> = Vec::new();

        for line in file_data.lines() {
            if let Ok(group) = Group::parse(line) {
                entries.push(group);
            }
        }

        Ok(entries)
    }
}

/// Gets the current process effective user id aborting the caller on error.
///
/// This function issues the `geteuid` system call returning the process effective
/// user id. In case of an error it will log message to `stderr` and then abort
/// the caller process with an non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let euid = get_euid();
///
/// ```
pub fn get_euid() -> usize {
    match syscall::geteuid() {
        Ok(euid) => euid,
        Err(_) => {
            eprintln!("redox_users: failed to get effective UID");
            exit(1)
        }
    }
}

/// Gets the current process real user id aborting the caller on error.
///
/// This function issues the `getuid` system call returning the process real
/// user id. In case of an error it will log message to `stderr` and then abort
/// the caller process with an non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let uid = get_uid();
///
/// ```
pub fn get_uid() -> usize {
    match syscall::getuid() {
        Ok(euid) => euid,
        Err(_) => {
            eprintln!("redox_users: failed to get real UID");
            exit(1)
        }
    }
}

/// Gets the current process effective group id aborting the caller on error.
///
/// This function issues the `getegid` system call returning the process effective
/// group id. In case of an error it will log message to `stderr` and then abort
/// the caller process with an non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let egid = get_egid();
///
/// ```
pub fn get_egid() -> usize {
    match syscall::getegid() {
        Ok(euid) => euid,
        Err(_) => {
            eprintln!("redox_users: failed to get effective GID");
            exit(1)
        }
    }
}

/// Gets the current process real group id aborting the caller on error.
///
/// This function issues the `getegid` system call returning the process real
/// group id. In case of an error it will log message to `stderr` and then abort
/// the caller process with an non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let gid = get_gid();
///
/// ```
pub fn get_gid() -> usize {
    match syscall::getgid() {
        Ok(euid) => euid,
        Err(_) => {
            eprintln!("redox_users: failed to get real GID");
            exit(1)
        }
    }
}

/// Gets the User representing given user ID aborting the caller on error.
///
/// This function will read the users database (currently '/etc/passwd')
/// returning a [`User`](struct.User.html) struct representing the
/// user who's UID matches and `None` otherwise. In case of an error
/// it will log message to `stderr` and then will exit the caller
/// process with an non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let user = get_user_by_id(1).unwrap();
///
/// ```
pub fn get_user_by_id(uid: usize) -> Option<User> {
    let passwd_file_entries = User::parse_file(PASSWD_FILE).unwrap();

    passwd_file_entries.iter()
        .find(|user| user.uid as usize == uid)
        .cloned()
}

/// Gets the User representing a user for a given username aborting the
/// caller on error.
///
/// This function will read the users database (currently '/etc/passwd')
/// returning a [`User`](struct.User.html) struct representing the user
/// who's username matches and `None` otherwise. In case of an error
/// it will log message to `stderr` and then will exit the caller
/// process an non-zero status code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let user = get_user_by_id(1).unwrap();
///
/// ```
pub fn get_user_by_name<T: AsRef<str>>(username: T) -> Option<User> {
    let passwd_file_entries = User::parse_file(PASSWD_FILE).unwrap();

    passwd_file_entries.iter()
        .find(|user| user.user == username.as_ref())
        .cloned()
}


/// Gets the group for a given group ID aborting the caller on error.
///
/// This function will read the user groups database (currently '/etc/group')
/// returning a [`Group`](struct.Group.html) struct representing the group
/// with a matching ID and `None` otherwise. In case of an error it will
/// log message to `stderr` and will exit the caller process with an
/// non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let group = get_group_by_id(1).unwrap();
///
/// ```
pub fn get_group_by_id(gid: usize) -> Option<Group> {
    let group_file_entries = Group::parse_file(GROUP_FILE).unwrap();

    group_file_entries.iter()
        .find(|group| group.gid as usize == gid)
        .cloned()
}

/// Gets the group for a given group name aborting the caller on error.
///
/// This function will read the user groups database (currently '/etc/group')
/// returning a [`Group`](struct.Group.html) struct representing the group
/// with a matching name and `None` otherwise. In case of an error it will
/// log message to `stderr` and will exit the caller process with an
/// non-zero exit code.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let group = get_group_by_name("wheel").unwrap();
///
/// ```
pub fn get_group_by_name<T: AsRef<str>>(groupname: T) -> Option<Group> {
    let group_file_entries = Group::parse_file(GROUP_FILE).unwrap();

    group_file_entries.iter()
        .find(|group| group.group == groupname.as_ref())
        .cloned()
}

/// An iterator over all the users in the system.
///
/// This function returns an [`AllUsers`](struct.AllUsers.html) iterator that
/// will yield [`User`](struct.User.html) instances representing each user
/// in the system.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let users = all_users();
///
/// for user in users {
///     // do something with the user
/// }
///
/// ```
pub fn all_users() -> AllUsers {
   AllUsers::new()
}

/// An iterator over all the users on the system.
///
/// This struct is generally created by calling [`all_users`](fn.all_users.html).
pub struct AllUsers {
    iter: std::vec::IntoIter<User>
}

impl AllUsers {
    pub fn new() -> AllUsers {
        let users = User::parse_file(PASSWD_FILE).unwrap();

        AllUsers { iter: users.into_iter() }
    }
}

impl Iterator for AllUsers {
    type Item = User;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

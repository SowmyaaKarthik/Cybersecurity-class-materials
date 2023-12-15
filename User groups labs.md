

# User Account Creation

### Scenario 

Let's consider that `John` has recently joined `ABC Consultancy Services` in the role of a `Software Developer`. As part of his onboarding process, the company needs to furnish him with a laptop, set up his user account with the appropriate group affiliation, and grant him the corresponding privileges based on his group. 

In this regard, it is necessary to include his name in the list of users associated with the software developer group.

**1.1 Create user `John` using `useradd`**

Syntax: `sudo useradd username`

```
sudo useradd John
```


This command creates a new user account with default settings. You may need to use sudo to run the command with administrative privileges.


**1.2 Creating the User Groups using `adduser`**

```
sudo adduser username
```

Again, replace username with the desired `username`.

The `adduser` command is a higher-level command that provides a more interactive interface for creating user accounts.

It prompts you to set the password, provide additional information like full name, phone number, etc., and allows you to customize various settings.

After running either of these commands, the new user account will be created, and you can set a password for the account.

You can then use the `su` command to switch to the newly created user account or the `sudo` command to execute commands with administrative privileges on behalf of that user.


## Creating User Groups"



**2.1 Creating the User Groups using `groupadd`**

To create a user group in a Linux terminal, you can use the groupadd command. Here's an example of how to create a group:

Using `groupadd `:

```
sudo groupadd groupname
```

Replace `groupname` with the desired username for the new user account.

This command creates a new user group with the specified name.


**2.2 Adding Users to Groups using `usermod `**

After running the groupadd command, the new group will be created on your system. You can then assign users to this group using the usermod command.

Using `usermod `:

```
sudo usermod -a -G groupname username
```

Again, replace username with the desired `username` and `groupname`.

The -a option appends the user to the group, and the -G option specifies the group name.

## Verifying the Users are added in the group

To verify whether users have been successfully added to a specific group in Linux, you can use the groups command or check the /etc/group file. Here are the steps:

**Using `groups `:**

```
groups username
```

Replace username with the `username` of the user you want to check. This command displays the groups that the specified user belongs to.

**Using `/etc/group `:**

```
grep 'groupname' /etc/group
```

or 

```
cat /etc/group
```

Replace `groupname` with the name of the group you want to verify. This command searches for the specified group name in the /etc/group file and displays the corresponding entry, including the group members.




## Authors

- <a href="https://www.linkedin.com/in/sowmyaa-gurusamy-b4a743202/" target="_blank">Sowmyaa Gurusamy</a>

No Copyrights are done.

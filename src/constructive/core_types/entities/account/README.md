# Account 👨‍💻
An `Account` is a user-controlled entity that serves as the primary actor within the system. It can initiate calls to `Contract`s to execute program logic or move satoshis to other `Account`s.

There are 2 core account types:

| Account Type     | Description                                        |
|:-----------------|:---------------------------------------------------|
| Account 👨‍💻       | Represents a distinct user within the system.      |
| Root Account 🥕  | An `Account` who calls an `Entry`.                 |

## Account 👨‍💻
Represents a distinct user within the system. Often the transactee and receiver.

## Root Account 🥕
Not to be confused with computer terminology, `Root Account` is essentially an `Account` who calls the `Entry`. Often the transactor and sender.
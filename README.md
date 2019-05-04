# PassList

## Purpose

Sometimes there is a need to password-protect your web-server, either in whole or just some parts of it.
That's were this package comes in.

## Installation

You can use `Go` to install this package for you:

    go get github.com/mwat56/go-passlist

## Usage

`PassList` provides an easy way to handle HTTP Basic Authentication by simply calling the package's `Wrap()` function and implementing the `TAuthDecider` interface which only requires the single function or method

    NeedAuthentication(aRequest *http.Request) bool

That function may decide on whatever means whether to grant access (returning `true`)) or deny it (returning `false`).
For your ease there are two `TAuthDecider` implementations provided: `TAuthSkipper` (which generally returns `false`) and `TAuthSkipper` (which generally returns `true`).
Just instanciate one of those – or, of course, your own implementation – and pass it to the `Wrap()` function.

    func Wrap(aHandler http.Handler, aRealm, aPasswdFile string, aAuthDecider TAuthDecider) http.Handler

The arguments mean:

* `aHandler`: the HTTP handler you implemented for your web-server; you will use the return value of `Wrap()` after you called this function.

* `aRealm`: the name of the host/domain to protect (this can be any string you like); it will be shown by most browsers when the username/password is requested.

* `aPasswdFile`: the name of the password file that holds all the username/password pairs to use when authentication is actually required.

* `aAuthDecider`: the deciding function we talked about above.

So, in short: implement the `TAuthDecider` interface and call `passlist.Wrap(…)`, and you're done.

However, the package provides a `TPassList` class with lots of methods to works with a username/password list.
It's fairly well documented, so it shouldn't be too hard to use it on your own if you don't like the automatic handling provided by `Wrap()`.
You can create a new instance by either calling `passlist.LoadPasswords(aFilename string)` (which, as it's name says, tries to load the given password file at once), or you call `passlist.NewList(aFilename string)` (which leaves it to you when to actually read the password file by calling the `TPassList` object's `Load()` method).

There's an additional convenience function called `passlist.Deny()` which sends an "Unauthorised" notice to the remote host in case the remote user couldn't be authenticated; this function is called internally whenever your `TAuthDecider` required authentication and wasn't given valid credentials from the remote user.

In the package's `_demo` folder you'll find the `pwaccess.go` program which implements the maintainance of password files with the following options:

    -add string
        <username> name of the user to add to the file (prompting for the password)
    -chk string
        <username> name of the user whose pass to check (prompting for the password)
    -del string
        <username> name of the user to remove from the file
    -file string
        <filename> name of the passwordfile to use (default "pwaccess.db")
    -lst
        list all current usernames from the list
    -q    whether to be quiet or not (suppress non-essential messages)
    -upd string
        <username> name of the user to update in the file (prompting for the password)

 > **Note**: To be on the safe side your web-server schould use `HTTPS` instead of plain old `HTTP` to avoid the chance of someone eavesdropping on the username/password exchange.

## Licence

    Copyright © 2019  M.Watermann, 10247 Berlin, Germany
                All rights reserved
            EMail : <support@mwat.de>

> This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
>
> This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
>
> You should have received a copy of the GNU General Public License along with this program.  If not, see the [GNU General Public License](http://www.gnu.org/licenses/gpl.html) for details.

# Yawning-crypto

Stuff, mirrored from github.com/Yawning/* to remove the dead references to git.schwanenlied.me/yawning/* repos.

The code is **&copy; Yawning Angel (yawning at schwanenlied dot me)**. I mirrored it, because the code in his github repos,
constantly import golang packages located at `git.schwanenlied.me/yawning/*` which down currently, and otherwise appeared to be unreliable somehow.

In these repo, you'll find code with working package-references.


## Disclaimer

**This is not done in an act of disrespect.** But if I find stuff, that's broken, I fix it. I was fed up by broken builds caused by

```go
import "git.schwanenlied.me/yawning/... .git/..."
```

and all that error messages because of that. My intention is to fix it.

##### Other reasons for forks:

Some packages add extensions, missing in the original Package. One example is this: [github.com/mad-day/newhope](https://github.com/mad-day/newhope), an implementation of **newhope**, forked to add the capability to export/import the private keys for use in IES-style encryption schemes.
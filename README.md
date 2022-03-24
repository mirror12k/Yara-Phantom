# Yara Phantom - imaginary malware!
Yara Phantom is a simple tool to take all the trouble of imagination away!
It creates a malicious-looking file by taking yara definitions, interpretting what they might look like, and inserting them into a binary.
By taking hundreds of these definitions at a time, we can start tripping AV agents by sheer terror-factor, all while still being absolutely harmless.

## How To Run
1. Insert your yara definitions into the `malware_yaras` folder.
2. Run `make run` to produce your incredibly harmless malware!

## The results speak for themselves:
https://www.virustotal.com/gui/file/f9b4867e65038932df583b0178f2d04097d7a9a1ca4d85b3f558a2d7647269b3

Not as amazing as I would have hoped, but downright malicious nevertheless.
This technique can be used to create spooky non-malware on demand,
or for testing AVs and their capability to distingush random garbage from actual malware.






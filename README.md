# q_spoke_space
A project to show a Qumulo spoke space vs the hub.

Qumulo Cloud Data Fabirc is a feature that allows a Qumulo instance (a hub) to share part of its filesystem with other Qumulo instnace (spokes).  The spoke acts as a cache and therefore, the space doesn't really count as "used" since it will be evicted as spoace on the spoke fills up.  But there may be times when you might want to know how much space the spoke is consuming in relation to the space the hub is sharing and that's what this project does.  It's a first draft, simple script that looks at a spoke, finds the associated hub, pulls space from both of them and shows the amount of space on each.  

The script simply requites Pyhon 3.x and the only module that may need to be added is 'keyring'. This can be done in the standard way via pip.

The script is run as follows:
<pre>
Usage: q_spoke_space.py [-hDS] [-c user] [-s user] [-H user] [-u unit] spoke:path
-h | --help : Prints Usage
-D | --DEBUG : Generated debug output
-s | --sooke_only : Only show stats on the spoke, not the hub
-c | --cred : Specify a common user on hub and spoke
-S | --spoke_user : Specify a spoke user
-H | --hub_user : Specify a hub user
-u | --unit : Specify a unit [kb, mb, gb, tb, pb]
</pre>

## Authentication
The API calls for the Qumulo clusters must be authenticated.   This script uses credentials which can be stored in the keyring in order to avoid re-typing them each time.  It can be made to work with tokens.  If that is desired, reach out to me or file an issue and I'll put that support in.  

## Units
By default, the script will convert the raw bytes into the largest unit that makes sense.  So for 1M bytes, it will report MB, etc.  If you want to standardize all the computations into a single unit, use the -u flag and specify the unit you like.  Only the first letter is used and it is case insensitive.

## Miminial Privildges: 

SPOKE:
<pre>
PORTAL_SPOKE_READ
PORTAL_GLOBAL_READ
FS_ATTRIBUTES_READ
</pre>

HUB:
<pre>
PORTAL_HUB_READ
FS_ATTRIBUTES_READ
</pre>

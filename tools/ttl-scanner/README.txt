# CODEMARK: nice-ibr
#
# Copyright (C) 2020-2024 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Distribution Statement "A" (Approved for Public Release,
# Distribution Unlimited).
#
# This material is based upon work supported by the Defense
# Advanced Research Projects Agency (DARPA) under Contract No.
# HR001119C0102.  The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of DARPA.
#
# In the event permission is required, DARPA is authorized to
# reproduce the copyrighted material for use as an exhibit or
# handout at DARPA-sponsored events and/or to post the material
# on the DARPA website.
#
# CODEMARK: end

HOW TO USE THE ttl-scanner
Version 1.0

I.  This directory contains tools for analyzing pcap files to find 
scanners targeting all hosts in a /24 network in which the
TTLs from the 256 packets display interesting patterns.

The input for these tools are pcap files, which may be uncompressed,
or compressed in .gz, .bz2, or .lz4 format.  Note that pcapng are, in
general, not supported -- some pcapng files will work properly, but
others will not.  The tools support pcap files with Ethernet, SLL, or
INET headers are supported by the current version; other DLT formats
can be added if required.

II. SETUP:

Please make sure to run ./setup.sh in the top directory. This will
install the packages needed to run the scripts here. It will install
python3 along with the python packages, like numpy and PIL used by 
these tools. It will also install sqlite3, a server-less database 
management.

This tool also requires the pktshow executable which should have
been installed by running the setup.sh script. The binary for 
pktshow relative to this directory is in ../../bin. The bin directory
is in the top directory at the same level as setup.sh.

III. RUNNING:

There is a script called, exHowToUse.sh in this directory and one
can simply run the script to see how the tools in the directory
should be used. For this script, the input and output directory is
the current directory where the script lives, and there is 
one example pcap, called ex-2021-09-26.pcap.gz.

Pcaps are the raw data.  Pktshow converts pcaps into csv files that
can be analyzed to find scans from sources that target all 256 hosts
in a network. Using those scans, also know as horizontal scans, the
TTL field is extracted.  If there is more than one TTL in that scan,
the TTL is given a color and stored in a 16x16 grid, indexed by
the host octet in the target address. Metadata is collected and then
entered into a sqlite3 database to facilitate searching the information.


Example of running exHowToUse.sh analyzing a single pcap file.

> ./exHowToUse.sh 

Example of output when exHowToUse.sh

pktshow ex-2021-09-26.pcap.gz
scan-display ./scans-2021-09-26.txt > ./summ-2021-09-26.txt
create-images-db

a) pktshow ex-2021-09-26.pcap.gz

The first step which is represented by the line: pktshow ..., 
reads a pcap file using pktshow, which converts the pcap into a csv
file that can be piped to the find-horiz-scans tool.
The find-horiz-scans tool looks for scans where a source tries to reach 
all 256 hosts of a /24 network. This steps outputs a file called scans-2021-09-26.txt.

On the command line it can be run:

    ../../bin/pktshow pcap1.pcap ... pcapN.pcap | ./find-horiz-scans > scans.txt

b) scan-display ./scans-2021-09-26.txt > ./summ-2021-09-26.txt

The second step represented by the line: scan-display ...,
uses the scan-display tool which creates a graphical representation of each
scan that has more than one TTL and analyzes the image for any interesting
symmetries. 

scan-display creates graphical representations of each scan that has
more than TTL, and puts them into OUTDIR, and also creates a summary
description of each scan and writes it to stdout. In this example, the images
directory is created in the current directory.  The images directory has 
a directory, pngfiles, where all unique graphical images can be found and
there will be a directory for each date that has a symbolic link to files
in the pngfiles directory.  That was done to be efficient about disk space.

i) The summary description in stdout, captured in summ-2021-09-26.txt, 
will have the following fields separated by spaces:

Output: filename of the png image
IP source: IP of the source attributed with the scan
Destination Subnet IP: IP /24 representation of the subnet
Elapsed Time: the total time of the /24 scan
Max TTL: greatest TTL in the /24 scan
Min TTL: smallest TTL in the /24 scan
TTL Count: total number of unique TTLs in the /24 scan
Pattern: refer to the TTL pattern description section below

ii) Pattern Description

To detect a pattern in the TTLs of the /24 scan, the first step is to
transform the TTLs of the /24 scan into a 16x16 matrix using the host
octet in the packet destination (for example, in the IP address
192.168.1.x, x is host octet) and the packet TTL.

Taking the host octet as the index into a 16x16 matrix, where the
top-left position is 0 and bottom-right position is 255 in left to
right order (sinistrodextral), each packet's TTL value is recorded
into the corresponding position in the matrix.

The next step is to detect patterns in this TTL matrix.

First, it creates a binary matrix based on sequential TTL values.  For
example, given the TTLS [235, 236, 237] for a scan, the TTL groupings
would be [235 | 236, 237], [235, 236 | 237], where everything to the
left of the bar is represented as zero and things to the right of the
bar are represented as one.

Each binary matrix is then divided into four quadrants:

 --------
| A | B |
|-------|
| C | D |
 --------

(4 choose 2) Relationships:
[(A, B), (A, C), (C, D), (B, D), (A, D), (B, C)]

Then, each of the quadrant pairs is tested for relationships
based on geometric transformations:

1. Stamp (S): both are the same pattern

2. Mirror (M): mirroring one quadrant along a specific axis (x or y),
    yields the same pattern as the other one (left-right(LR),
    up-down(UD))

3. Rotational (R): rotating one quadrant yields the same pattern as
    the other one (90, 180, 270)

Additionally, these are checked on the logical not of one quadrant.
This is indicated below with an n, such that AnB implies the
comparison between A and logical not of B.

Note: there are additional compounds of patterns that this function
does not detect, such as a combination of being mirrored and rotated,
for example.

The following is the list of patterns the algorithm detects. For
example, MUD-CD would correspond to the pattern mirror up-down for
quadrants C and D.

['S_AB', 'MUD_AB', 'MLR_AB', 'R90_AB', 'R180_AB', 'R270_AB',
 'S_AC', 'MUD_AC', 'MLR_AC', 'R90_AC', 'R180_AC', 'R270_AC',
 'S_CD', 'MUD_CD', 'MLR_CD', 'R90_CD', 'R180_CD', 'R270_CD',
 'S_DB', 'MUD_DB', 'MLR_DB', 'R90_DB', 'R180_DB', 'R270_DB',
 'S_AD', 'MUD_AD', 'MLR_AD', 'R90_AD', 'R180_AD', 'R270_AD',
 'S_BC', 'MUD_BC', 'MLR_BC', 'R90_BC', 'R180_BC', 'R270_BC',
 'S_AnB', 'MUD_AnB', 'MLR_AnB', 'R90_AnB', 'R180_AnB', 'R270_AnB',
 'S_AnC', 'MUD_AnC', 'MLR_AnC', 'R90_AnC', 'R180_AnC', 'R270_AnC',
 'S_CnD', 'MUD_CnD', 'MLR_CnD', 'R90_CnD', 'R180_CnD', 'R270_CnD',
 'S_DnB', 'MUD_DnB', 'MLR_DnB', 'R90_DnB', 'R180_DnB', 'R270_DnB',
 'S_AnD', 'MUD_AnD', 'MLR_AnD', 'R90_AnD', 'R180_AnD', 'R270_AnD',
 'S_BnC', 'MUD_BnC', 'MLR_BnC', 'R90_BnC', 'R180_BnC', 'R270_BnC']

In the output, we concatenate the patterns using a ",", such that a
/24 scan can contain multiple of these relationships. The algorithm
also records the TTL that was used as the threshold to establish the
binary groupings on the matrix. Therefore, an output like:

max_ttl 51 min_ttl 48 ttl_cnt 3 pattern {50.0: 'S_AB,MUD_DB,MUD_AD'}

would indicate that the binary groupings were (48, 50) => 0 and (51)
=> 1 and that the pattern found in that /24 scan contains three
relationships (B is a stamp of A, B is mirror up-down of D, and D is
mirror up-down of A)

There exist cases when a scan can have different patterns based on the
groupings, this would be indicated by having more than one key in the
pattern field.


iii) Interesting Patterns

The following are extra interesting TTL pattern descriptions, we
encourage the user to keep an eye out for:

MUD_AB,R270_AB,MLR_AC,R90_AC,MUD_CD,R90_CD,MLR_DB,R270_DB,R180_AD,R180_BC

MUD_AB,MUD_CD,MUD_AnC,MUD_DnB,S_AnD,S_BnC

On the command line it can be run:

  ./scan-display -d OUTDIR scans.txt > summary.txt


c) create-images-db

The third step represented by the line: create-images-db

create-images-db is provided to look at the summary files
created by scan-display and make an sqlite3 database. This command creates
a sql file that is used to create the database. Both the sql file and 
the database are created by this command i.e. dbPrefix.sql and dbPrefix.db

This prints 2 lines following this format:
    SQL statements written to dbPrefix.sql
    dbPrefix.db is created from dbPrefix.sql
    

On the command line it can be run:

  ./create-images-db -p dbPrefix scan-*summary.txt 

a) Database Details
This is the current schema.

--Tentative Schema to help with looking for instances of
--interesting symmetrical images
CREATE TABLE IF NOT EXISTS "images"
(
    [ImageId] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    [Fname] TEXT NOT NULL,
    [DHash] TEXT NOT NULL,
    [NHash] TEXT NOT NULL,
    [InterestVal] INT NOT NULL,
    UNIQUE(DHash, NHash)
);

CREATE TABLE IF NOT EXISTS "instances"
(
    [InstanceId] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    [Src] TEXT NOT NULL,
    [Dst] TEXT NOT NULL,
    [Proto] INTEGER NOT NULL,
    [DPort] INTEGER NOT NULL,
    [Tstamp] TEXT NOT NULL,
    [Dur] REAL NOT NULL,
    [ImageId] INTEGER,
    [MinTTL] INTEGER NOT NULL,
    [MaxTTL] INTEGER NOT NULL,
    [NumTTLs] INTEGER NOT NULL,
    [TTLs] JSON NOT NULL,
    [DHash] TEXT NOT NULL,
    [NHash] TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "patterns"
(
    [PatternId] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    [DHash] TEXT NOT NULL,
    [NHash] TEXT NOT NULL,
    [TTL] INTEGER NOT NULL,
    [MLR_AB] BOOLEAN DEFAULT 0, 
    [MLR_AC] BOOLEAN DEFAULT 0, 
    [MLR_AD] BOOLEAN DEFAULT 0, 
    [MLR_AnB] BOOLEAN DEFAULT 0, 
    [MLR_AnC] BOOLEAN DEFAULT 0, 
    [MLR_AnD] BOOLEAN DEFAULT 0, 
    [MLR_BC] BOOLEAN DEFAULT 0, 
    [MLR_BnC] BOOLEAN DEFAULT 0, 
    [MLR_CD] BOOLEAN DEFAULT 0, 
    [MLR_CnD] BOOLEAN DEFAULT 0, 
    [MLR_DB] BOOLEAN DEFAULT 0, 
    [MLR_DnB] BOOLEAN DEFAULT 0, 
    [MUD_AB] BOOLEAN DEFAULT 0, 
    [MUD_AC] BOOLEAN DEFAULT 0, 
    [MUD_AD] BOOLEAN DEFAULT 0, 
    [MUD_AnB] BOOLEAN DEFAULT 0, 
    [MUD_AnC] BOOLEAN DEFAULT 0, 
    [MUD_AnD] BOOLEAN DEFAULT 0, 
    [MUD_BC] BOOLEAN DEFAULT 0, 
    [MUD_BnC] BOOLEAN DEFAULT 0, 
    [MUD_CD] BOOLEAN DEFAULT 0, 
    [MUD_CnD] BOOLEAN DEFAULT 0, 
    [MUD_DB] BOOLEAN DEFAULT 0, 
    [MUD_DnB] BOOLEAN DEFAULT 0, 
    [R180_AB] BOOLEAN DEFAULT 0, 
    [R180_AC] BOOLEAN DEFAULT 0, 
    [R180_AD] BOOLEAN DEFAULT 0, 
    [R180_AnB] BOOLEAN DEFAULT 0, 
    [R180_AnC] BOOLEAN DEFAULT 0, 
    [R180_AnD] BOOLEAN DEFAULT 0, 
    [R180_BC] BOOLEAN DEFAULT 0, 
    [R180_BnC] BOOLEAN DEFAULT 0, 
    [R180_CD] BOOLEAN DEFAULT 0, 
    [R180_CnD] BOOLEAN DEFAULT 0, 
    [R180_DB] BOOLEAN DEFAULT 0, 
    [R180_DnB] BOOLEAN DEFAULT 0, 
    [R270_AB] BOOLEAN DEFAULT 0,
    [R270_AC] BOOLEAN DEFAULT 0,
    [R270_AD] BOOLEAN DEFAULT 0,
    [R270_AnB] BOOLEAN DEFAULT 0,
    [R270_AnC] BOOLEAN DEFAULT 0,
    [R270_AnD] BOOLEAN DEFAULT 0,
    [R270_BC] BOOLEAN DEFAULT 0,
    [R270_BnC] BOOLEAN DEFAULT 0,
    [R270_CD] BOOLEAN DEFAULT 0,
    [R270_CnD] BOOLEAN DEFAULT 0,
    [R270_DB] BOOLEAN DEFAULT 0,
    [R270_DnB] BOOLEAN DEFAULT 0,
    [R90_AB] BOOLEAN DEFAULT 0, 
    [R90_AC] BOOLEAN DEFAULT 0, 
    [R90_AD] BOOLEAN DEFAULT 0, 
    [R90_AnB] BOOLEAN DEFAULT 0, 
    [R90_AnC] BOOLEAN DEFAULT 0, 
    [R90_AnD] BOOLEAN DEFAULT 0, 
    [R90_BC] BOOLEAN DEFAULT 0, 
    [R90_BnC] BOOLEAN DEFAULT 0, 
    [R90_CD] BOOLEAN DEFAULT 0, 
    [R90_CnD] BOOLEAN DEFAULT 0, 
    [R90_DB] BOOLEAN DEFAULT 0, 
    [R90_DnB] BOOLEAN DEFAULT 0, 
    [S_AC] BOOLEAN DEFAULT 0, 
    [S_AB] BOOLEAN DEFAULT 0, 
    [S_AD] BOOLEAN DEFAULT 0, 
    [S_AnB] BOOLEAN DEFAULT 0, 
    [S_AnC] BOOLEAN DEFAULT 0, 
    [S_AnD] BOOLEAN DEFAULT 0, 
    [S_BC] BOOLEAN DEFAULT 0, 
    [S_BnC] BOOLEAN DEFAULT 0, 
    [S_CD] BOOLEAN DEFAULT 0, 
    [S_CnD] BOOLEAN DEFAULT 0, 
    [S_DB] BOOLEAN DEFAULT 0, 
    [S_DnB] BOOLEAN DEFAULT 0,
    UNIQUE(DHash, NHash, TTL)
);


b) How to recreate the database
  - sqlite3 dbPrefix.db < dbPrefix.sql

c) Interesting queries
  - echo "select NHash, Count(*) from instances Group by NHash Having Count(*) > 9;" | sqlite3 dbPrefix.db > bycount
  - echo "select NHash from patterns where MUD_AB=1 and R270_AB=1 and MLR_AC=1 and R90_AC=1 and MLR_DB=1 and R270_DB=1 and R180_AD=1 and R180_BC=1;" | sqlite3 dbPrefix.db > intpatterns
  - echo "select NHash from patterns where MUD_AB=1 and MUD_CD=1 and MUD_AnC=1 and MUD_DnB=1 and S_AnD=1 and S_BnC=1;" | sqlite3 dbPrefix.db > intpatterns

d) Output artifacts:
   - There will be txt files that list scans that target all 256 hosts in a /24 network, named scans-"date".txt.
   - There will be txt files that describe what was found from those scans, named summ-"date".txt. 
     Each line is comma delimited with the following fields: 
       Output: filename of the png image
       IP source: IP of the source attributed with the scan
       Destination Subnet IP: IP /24 representation of the subnet
       Elapsed Time: the total time of the /24 scan
       Max TTL: greatest TTL in the /24 scan
       Min TTL: smallest TTL in the /24 scan
       TTL Count: total number of unique TTLs in the /24 scan 
       Pattern: refer to the TTL pattern description section above
   - png files in the $OUTDIR/images directory: each day is its own directory with links to files in $OUTDIR/imgages/pngFiles
   - a sql file to create an sqlite3 db
   - an sqlite3 db to facilitate searching for information

ADDENDUM:

Another useful command that creates a database from all scans is:
    
   create-scan-db

create-images-db creates a database with scans that have interesting
images looking at the TTL field.  In the event, all scans may be of 
interest, this tool is provided.

On the command line it can be run:
   create-scan-db -p output -o outDir /inputdir/scans*.txt 

   Input: text files of scans from 

           ../bin/pktshow "$PCAPDIR"/"Dates"-*.pcap.gz \
                    | ./find-horiz-scans -t 600

           pktshow takes pcap files and outputs packets that are fed into
           find-horiz-scans - the -t parameter is customizable

   Output: prints to file output.sql used to populate output.db
           default is to output in current directory
           or optionally outDir/output.sql outDir/output.db



a) Database Details
This is the current schema.
        
--Tentative Schema to count /24 scans

"CREATE TABLE IF NOT EXISTS "instances"
(
    [InstanceId] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    [Src] TEXT NOT NULL,
    [Dst] TEXT NOT NULL,
    [Proto] INTEGER NOT NULL,
    [DPort] INTEGER NOT NULL,
    [Tstamp] TEXT NOT NULL,
    [Dur] REAL NOT NULL,
    [Cov] INTEGER NOT NULL,
    [Cnt] INTEGER NOT NULL,
    [Inv] INTEGER NOT NULL
);


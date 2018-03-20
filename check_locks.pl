#!/usr/bin/perl -w
#
# locks-chan
# version 1.1
#
# / i felt the rise of that old familiar feeling. i hated it. /
#

# modules
use strict;
use DBI;
use Getopt::Std;
use List::Util qw(min max);
use Encode;
use POSIX 'strftime';

# user specific
my $logfile = "/u01/log/nagios/check_locks.log";

# args
my %args;
getopts('d:hl:np:stu:', \%args) or die "Input error. Use -h.\n";
my $sid = $args{d};
my $user = $args{u};
my $pwd = $args{p};
#my $limit = $args{l};
my $limit = defined($args{l}) ? $args{l} : 0;
my $line = "";
my $wline = "";
my @array = ( );
my @out = ( );
my @tlocks = ( );
my %culprit;
my $ec = "";
my ($sid1,$osuser1,$username1,$sid2,$osuser2,$username2,$program,$sqlid,$sqltext,$prevsql,$previd,$prevprogram);
my ($sid3,$ora_user,$object_name,$object_type,$lock_mode,$status,$last_ddl,$logon,$wait_secs,$then,$date);

# help
my $help = "\n\tcheck_locks.pl - check if there are locks in database.\n \
        check_locks.pl [-hnst] -d <DATABASE> [-l <TIME_LIMIT>] -u <USER> -p <PWD>\n \
        -d - database name. \
        -h - print this message. \
        -l - optional time limit when to alert about possible locks (in seconds).\
        -n - no html formatting. \
        -p - user password. \
        -s - silent output (only number of locks, if any). \
        -t - table locks. \
        -u - database user.\n\n";

# checks
if ($args{h}) { print $help; exit 1; }
if (!$args{d} || !$args{u} || !$args{p}) { print "Input error. Use -h.\n"; exit 1; }

# error output
sub handle_error {
   my $emessage = shift;
   $emessage = Encode::decode('cp1251',$emessage);
   print "WARNING - ".$emessage.".\n";
   exit 1;
}

# db connect
$ENV{NLS_LANG} = "AMERICAN_AMERICA.CL8MSWIN1251";
my $dbh = DBI->connect( 'dbi:Oracle:'.$sid,$user,$pwd, {HandleError => \&handle_error});

# table locks
if ($args{t}) {
   my $check_table = q{

      select l.session_id,
             l.oracle_username ora_user,
             o.object_name, 
             o.object_type, 
             decode(l.locked_mode,
                0, 'None',
                1, 'Null',
                2, 'Row-S (SS)',
                3, 'Row-X (SX)',
                4, 'Share',
                5, 'S/Row-X (SSX)',
                6, 'Exclusive', 
                to_char(l.locked_mode)
             ) lock_mode,
             o.status, 
             to_char(o.last_ddl_time,'dd.mm.yy') last_ddl
      from dba_objects o, gv$locked_object l, v$session v
      where o.object_id = l.object_id
      and l.session_id=v.sid
      order by 2,3

   };

   my $sth = $dbh->prepare($check_table);
   $sth->execute();

   $sth->bind_columns(undef, \$sid3, \$ora_user, \$object_name, \$object_type, \$lock_mode, \$status, \$last_ddl);

   while( $sth->fetch() ) {
      #print "$sid3, $ora_user, $object_name, $lock_mode, $status, $last_ddl\n";
      push(@tlocks, sprintf "%-12s | %-12s | %-30s | %-20s | %-5s | %-10s\n", $sid3, $ora_user, $object_name, $object_type, $lock_mode, $status, $last_ddl);
   }

   # output
   if (scalar @tlocks == 0) {
      print "No information was found for table lock(s).\n";
      print "-" x 41;
      print "\n";
   }
   else {
      print "Table lock(s) present:\n";
      print "-" x 22;
      print "\n";
      printf ("%-14s %-14s %-32s %-22s %-12s %-10s\n", "SID", "Username", "Object", "Type", "Mode", "Status", "Last DDL");
      print "_" x 105;
      print "\n";
      foreach $line (@tlocks) { print "$line"; }
      print "\n";
   }

   $sth->finish();
   print "Session lock(s) present:\n";
   print "-" x 24;
   print "\n";
}

# main locks
my $check_locks = qq{

   select distinct s2.sid,
                   s2.osuser,
                   s2.username,
                   s1.sid,
                   s1.osuser,
                   s1.username,
                   substr((select distinct sql_text from v\$sql where sql_id=s3.sql_id),1,40),
                   s3.sql_id,
                   s2.program,
                   substr((select distinct sql_text from v\$sql where sql_id=s4.sql_id),1,40),
                   s1.program,
                   s4.sql_id,
                   (s1.logon_time-to_date('1970-01-01', 'YYYY-MM-DD'))*86400000,
                   s2.seconds_in_wait
   from sys.v_\$lock l1,
        sys.v_\$session s1,
        sys.v_\$lock l2,
        sys.v_\$session s2,
        sys.v_\$sql s3,
        sys.v_\$sqltext s4
   where s1.sid = l1.sid
     and s2.sid = l2.sid
     and l1.block = 1
     and l2.request > 0
     and l1.id1 = l2.id1
     and s2.sql_id = s3.sql_id
     and s1.prev_sql_id = s4.sql_id
     and s2.seconds_in_wait > $limit

};

my $sth = $dbh->prepare($check_locks);
$sth->execute();

$sth->bind_columns(undef, \$sid2, \$osuser2, \$username2, \$sid1, \$osuser1, \$username1, \$sqltext, \$sqlid, \$program, \$prevsql, \$prevprogram, \$previd, \$logon, \$wait_secs);

# violet - A7005F
my $fv = "<b><font color='#A7005F'>";
# green - 005F5F
my $fg = "<b><font color='#005F5F'>";
# blue - 32334E
my $fb = "<b><font color='#32334E'>";

my $fc = "</b></font>";
my $i = 0;
my ($sind,$pind);

while( $sth->fetch() ) {
   chop($prevsql);
   if ($sqltext =~ m/\|/) {
      $pind = index($sqltext, "|");
      $sqltext = substr($sqltext,0,$pind);
   }
   if ($prevsql =~ m/\|/) {
      $sind = index($prevsql, "|");
      $prevsql = substr($prevsql,0,$sind);
   }
   if (length($prevsql) != 0) {
      $then = time - $wait_secs;
      $date = strftime ('%Y.%m.%d %H:%M:%S', localtime $then);
      push(@array, sprintf "-- SID = $fg$sid2$fc on $fb$osuser2$fc (logged as $fb$username2$fc)\n  with CURRENT statement \"$fv$sqltext$fc...\" (SQL_ID: $fv$sqlid$fc, $fv$program$fc)\nis blocked by SID = $fg$sid1$fc on $fb$osuser1$fc (logged as $fb$username1$fc)\n  with PREVIOUS statement \"$fv$prevsql$fc...\" (SQL_ID: $fv$previd$fc, $fv$prevprogram$fc)\nfor $wait_secs seconds (since $date).");
      push(@out, sprintf "SID = $sid2 on $osuser2 (logged as $username2)\n     with CURRENT statement \"$sqltext...\" (SQL_ID: $sqlid, $program)\n   is blocked by SID = $sid1 on $osuser1 (logged as $username1)\n     with PREVIOUS statement \"$prevsql...\" (SQL_ID: $previd, $prevprogram)\n   for $wait_secs seconds (since $date).");
      %culprit = (%culprit, $sid1, $logon);
   }
}

$sth->finish();
$dbh->disconnect;

my $len = @array;
open F, ">>$logfile";

if ($len > 0) {
   print "WARNING - There are $len blocking sessions\n\n";
   my $chan = (sort {$culprit{$a} <=> $culprit{$b}} keys %culprit)[0];
   print "Could be caused by SID = $chan\n";
   if ($len > 20) {
      print "Top 20 sessions listed below:\n";
   }
   if ($args{s}) { exit 1; }
   else {
      if ($args{n}) {
         foreach $line (@out) {
            print "-- $line\n";
         }
      }
      else {
         if ($len <= 20) {
            foreach $line (@array) {
               print "$line\n";
            }
         }
         else {
            while ($i < 21) {
               print "$array[$i]\n";
               ++$i;
            }
         }
      }
   }
   print " | locks=$len";
   print F "-----------------------------------------\n".localtime(time())." Instance = $sid\n\n";
   foreach $wline (@out) {
      print F "-- $wline\n";
   }
   $ec = 1;
}
else {
   print "OK - No blocking sessions | locks=0\n";
   $ec = 0;
}

# close log file
close F;

# exit
exit $ec;

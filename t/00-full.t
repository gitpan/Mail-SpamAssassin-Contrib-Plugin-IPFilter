#!/usr/bin/perl

use strict;
use Test::More;
use Email::Simple;

use MIME::Base64 qw(encode_base64 decode_base64);
use POSIX qw(strftime setsid :sys_wait_h);
use Mail::SpamAssassin;
use Math::Round qw(nearest round);
use Hash::Util qw(lock_hashref);
use Redis;
#use Data::Dumper;

my ($sa, $msg, $email, $status, $redis, $rserver, $rhost, $rport, $rauth, $rkey, $debug, $v, $a, $b, $c, $d, $iptables);
$debug = '';
#$debug = 'info';
#$debug = 'all';

sub find_bin {
	my ($bin, @path, $p);
	$bin = shift;
	@path = ('/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin','/usr/local/sbin');
	foreach $p (@path){
		return $p.'/'.$bin if (-e $p.'/'.$bin);
	}
}

sub redis_state {
	return if(!$debug);
	print "\nRedis:\n";
	map{print "\t".$_.' => '.$redis->get($_)."\n"} @{[$redis->keys($rkey.'*')]};	
	print "\n";
}

ok(find_bin('iptables'), 'Found iptables binary') || die('Could not find iptables binary');
$iptables = find_bin('flock') ? find_bin('flock') . ' /var/lock/spamipfilter -c "' . find_bin('iptables') : find_bin('iptables');

$rauth = '';
$rserver = '127.0.0.1:6379';
$rkey = 'spamipfiltertest';
$redis = length($rauth)>0 ? Redis->new(server => $rserver, password => $rauth) : Redis->new(server => $rserver);
if(!$redis->ping){
	diag("\nredis server [$rserver]>");
	$rserver = <STDIN>;
	chomp($rserver);
	diag('redis password [none]>');
	system(find_bin('stty'), '-echo') if(find_bin('stty'));
	$rauth = <STDIN>;
	system(find_bin('stty'), 'echo') if(find_bin('stty'));
	chomp($rauth);	
	$rserver =~ s/[\r\n\t ]//g;
	$rauth =~ s/[\r\n\t ]//g;
	$rserver = '127.0.0.1:6379' if(!$rserver);
	$redis = length($rauth)>0 ? Redis->new(server => $rserver, password => $rauth) : Redis->new(server => $rserver);
	die("Could not connect to redis via $rserver") if(!$redis->ping);
	$redis->set('spamipfiltertest' => 7);
	if( 7 != $redis->get('spamipfiltertest')){
		$redis->quit;
		die('Could not connect to redis using the supplied password');
	}
}

map{$redis->del($_)} @{[$redis->keys($rkey.'*')]};

($rhost, $rport) = split(':', $rserver);
$rauth = "ipfilter_redis_auth $rauth" if(0<length($rauth));
$sa = Mail::SpamAssassin->new({debug=>$debug, local_tests_only=>1, config_text=>"required_score 4\nheader IPFSPAM Subject =~ /ipfilter\\_spam/i\nscore IPFSPAM 7\nheader IPFHAM Subject =~ /ipfilter\\_ham/i\nscore IPFHAM 1\nloadplugin Mail::SpamAssassin::Plugin::Check\nloadplugin Mail::SpamAssassin::Contrib::Plugin::IPFilter\nipfilter_redis_host $rhost\nipfilter_redis_port $rport\n$rauth\nipfilter_redis_key_prefix $rkey\nipfilter_verbose 1\nipfilter_trigger_score 6\nipfilter_trigger_messages 3\nipfilter_trigger_sensitivity 4\nipfilter_average_score_for_rule 8\nipfilter_expire_rule_seconds 7200\nipfilter_seconds_to_decay_penalty 300\nipfilter_expires_multiplier_penalty 1.5\nipfilter_cache_decay_days 2"});

$msg = Email::Simple->create(
	header => [
		From    => 'root@localhost.localdomain',
		To      => 'root@localhost.localdomain',
		Subject => '<ipfilter_spam>',
		Received => "from localhost.localdomain (localhost.localdomain [198.51.100.1])\n\tby mail.localhost.localdomain (Postfix) with ESMTPS id 9FF9F90090F\n\tfor <root\@localhost.localdomain>; ".strftime('%a, %e %b %Y %H:%M:%S +0000 (UTC)', gmtime),
	],
	body => '...',
)->as_string;

redis_state();

$status = $sa->check_message_text($msg);
redis_state();
$v = $redis->get('spamipfiltertest-198.51.100.1') || '';
ok($v =~ /^([0-9.]+),([0-9.]+),1,([0-9]+),(.*)$/, 'Found record for {spamipfiltertest-198.51.100.1} : '.$v);
$a = $b = 0;
if(($1)&&($2)){
	$v = $1.','.$2.',1,'. ($3 - 600) .','.$4;
	$a = $1 + 0.0;
	$b = $2 + 0.0;
	$redis->set('spamipfiltertest-198.51.100.1' => $v);
}

redis_state();

$status = $sa->check_message_text($msg);
$v = $redis->get('spamipfiltertest-198.51.100.1') || '';
ok($v =~ /^([0-9.]+),([0-9.]+),2,([0-9]+),(.*)$/, 'Found updated record for {spamipfiltertest-198.51.100.1} : '.$v);
$c = $d = -1;
if(($1)&&($2)){
	$c = $1 + 0.0;
	$d = $2 + 0.0;
}
ok($c>$a && $d>$b, 'Record {spamipfiltertest-198.51.100.1} was correctly updated on receipt of second spam msg : '."$c>$a && $d>$b"); 
redis_state();


$status = $sa->check_message_text($msg);
$v = $redis->get('spamipfiltertest-198.51.100.1') || '';

ok($v =~ /^([0-9.]+),([0-9.]+),3,([0-9]+),(.*)$/, 'Found updated record for {spamipfiltertest-198.51.100.1 : '.$v);
$c = $d = -1;
if(($1)&&($2)){
	$c = $1 + 0.0;
	$d = $2 + 0.0;
}
redis_state();

$msg =~ s/<ipfilter_spam>/<ipfilter_ham>/i;
$status = $sa->check_message_text($msg);
redis_state();
$v = $redis->get('spamipfiltertest-198.51.100.1') || '';
ok($v=~/^([0-9.]+),([0-9.]+),2,([0-9]+),(.*)$/, 'Found updated record for {spamipfiltertest-198.51.100.1} : '.$v);
$a = $b = 0;
if(($1)&&($2)){
	$a = $1 + 0.0;
	$b = $2 + 0.0;
}
ok($c>$a && $d>$b, 'Record {spamipfiltertest-198.51.100.1} was correctly updated on receipt of ham msg : '."$c>$a && $d>$b");


$v = $redis->get('spamipfiltertest') || 0;
$v =~s/\:.*$//;
$v = (int($v) - 7202).':11';
$redis->set('spamipfiltertest' => $v);
$v = $redis->get('spamipfiltertest-198.51.100.1') || '';
ok($v =~ /^([0-9.]+,[0-9.]+,[0-9]+),([0-9]+),(.*)$/, 'Found updated record for {spamipfiltertest-198.51.100.1} : '.$v);
if(($1)&&($2)){
	$a = $2 - 86400;
	$v = $1.','. $a .','.$3;
	$redis->set('spamipfiltertest;expires-198.51.100.1' => $a);
	$redis->set('spamipfiltertest-198.51.100.1' => $v);
}	
$v = $iptables. ' -F spamipfilter';
$v .= '"' if ($iptables =~ /\/flock /i);
system($v);
$v = $iptables. ' -t filter -I spamipfilter -i eth+ -s 198.51.100.1 -j DROP -m comment --comment \'expires='.$a.'\'';
$v .= '"' if ($iptables =~ /\/flock /i);
system($v);

$msg = Email::Simple->create(
        header => [
                From    => 'ipfiltertest_42@gmail.com',
                To      => 'root@localhost.localdomain',
                Subject => '<ipfilter_ham>',
                Received => "from test.google.com (test.google.com [198.51.100.2])\n\tby mail.localhost.localdomain (Postfix) with ESMTPS id 9FF9F90090F\n\tfor <root\@localhost.localdomain>; ".strftime('%a, %e %b %Y %H:%M:%S +0000 (UTC)', gmtime),
        ],
        body => '...',
)->as_string;

$status = $sa->check_message_text($msg);
redis_state();

sleep(2);

=cut
$v = $iptables. ' -L spamipfilter';
$v .= '"' if ($iptables =~ /\/flock /i);
$v = `$v`;
ok($v !~ /198\.51\.100\.1/,'IPTables rule for 198.51.100.1 was cleared') || warn($v);
=cut

$msg =~ s/<ipfilter_ham>/<ipfilter_spam>/i;
$status = $sa->check_message_text($msg);

$v = $redis->get('spamipfiltertest;expires-198.51.100.1') || '';
ok(!$v, 'spamipfiltertest;expires-198.51.100.1 was cleared : '.$v);
$v = $redis->get('spamipfiltertest-'.encode_base64('ipfiltertest_42','').'@google.com') || '';
ok($v =~ /^([0-9.]+,[0-9.]+,[0-9]+),([0-9]+),198\.51\.100\.2$/, 'spamipfiltertest-ipfiltertest_42@google.com was set : '.$v);

redis_state();

$status = $sa->check_message_text($msg);
redis_state();

$status = $sa->check_message_text($msg);
redis_state();

$v = $redis->get('spamipfiltertest-'.encode_base64('ipfiltertest_42','').'@google.com') || '';
ok($v =~ /^([0-9.]+),([0-9.]+),[1-9],([0-9]+),(.*)$/, 'Found record for {spamipfiltertest-ipfiltertest_42@google.com} : '.$v);

$v = $redis->get('spamipfiltertest') || 0;
$v =~s/\:.*$//;
$v = (int($v) - 7202).':11';
$redis->set('spamipfiltertest' => $v);
$v = $redis->get('spamipfiltertest-'.encode_base64('ipfiltertest_42','').'@google.com') || '';
ok($v =~ /^([0-9.]+,[0-9.]+,[0-9]+),([0-9]+),(.*)$/, 'Found record for {spamipfiltertest-ipfiltertest_42@google.com} : '.$v);
if(($1)&&($2)){
	$a = $2 - 86400;
	$v = $1.','. $a .','.$3;
	$redis->set('spamipfiltertest;expires-'.encode_base64('ipfiltertest_42','').'@google.com' => $a);
	$redis->set('spamipfiltertest-'.encode_base64('ipfiltertest_42','').'@google.com' => $v);
}
$msg =~ s/<ipfilter_spam>/<ipfilter_ham>/i;

$status = $sa->check_message_text($msg);
sleep(2);
redis_state();

#print $status->get_score();

$sa->finish();
$redis->quit;

done_testing();

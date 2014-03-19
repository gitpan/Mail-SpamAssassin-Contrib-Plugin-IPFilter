package Mail::SpamAssassin::Contrib::Plugin::IPFilter;

# ABSTRACT: Blocks bad MTA behavior using IPTables and Redis.

# <@LICENSE>
#
# Copyright 2014 Tamer Rizk, Inficron Inc. <foss[at]inficron.com>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution. 
# 
#   * Neither the name of Tamer Rizk, Inficron Inc, nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# </@LICENSE>

# Author:  Tamer Rizk <foss[at]inficron.com>


use strict;
use Redis;
use MIME::Lite;
use MIME::Base64 qw(encode_base64 decode_base64);
use Math::Round qw(nearest round);
use Hash::Util qw(lock_hashref);

use vars qw($VERSION @ISA);
my ($Verbose, %Regex);

$VERSION = 0.9.2;

sub update {
	my $buf = shift;

	die('Nothing to update') if(!$buf);
	my (%conf, @buffer, $v, $redis, $expires, $iptables, $re);

	$re = \%Regex;
	$expires = time();

	map{ $_ =~ $re->{param} ? ($conf{$1} = $2) : die("IPFilter [update]: Invalid param $_") } split('&', decode_base64($buf));
	die('IPFilter [update]: Invalid number of params '.join(',', keys %conf)) if (int(split('\x29\x7c\x28\x3f\x3a', sprintf('%s',$re->{param}))) != int(keys %conf));

	$conf{re} = $re;

	$iptables = $conf{iptables_bin}.' -L '.$conf{filter_name}.' -n -v -x';
	$iptables = `$iptables`;

	$redis = redis_connect(\%conf);
	if($conf{admin_email}){
		@buffer = localtime();
		clean_notifications($redis, {conf => \%conf}) if ($buffer[6]==6 && $buffer[2]==2);
		notify_blacklist($redis, {conf => \%conf});
	}
	refresh_iptables($redis, {conf => \%conf, iptables => $iptables});	
	$redis->quit;

	@buffer = ();
	map{ $_ =~ $re->{expires} && ($1) && $expires > int($2) && (push @buffer, iptables_safe_cmd('-t filter -D '.$conf{filter_name}.' -i eth+ -s '.sanitize($1, $re->{ipn}, '198.51.100.0').' -j DROP -m comment --comment \'expires='.int($2).'\'', \%conf)) } split("\n", $iptables);
	op_batch(\@buffer, \&clean_rules, {conf => \%conf}) if (@buffer);
	
	$redis->quit;
	exit;
}

sub inform {
	return if ($Verbose != 1);
	sub_exists('info') ? info('IPFilter: '.$_[0]) : warn('IPFilter: '.$_[0]);
}

sub debug {
	return if ($Verbose != 1);
	sub_exists('dbg') ? dbg('IPFilter: '.$_[0]) : warn('IPFilter: '.$_[0]);
}

sub error {
	warn('IPFilter: '.$_[0]);
	#log_message('error', 'IPFilter: '.$_[0]);
}

sub find_bin {
	my ($bin, @path, $p);
	$bin = shift;
	@path = ('/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin','/usr/local/sbin');
	foreach $p (@path){
		return $p.'/'.$bin if (-e $p.'/'.$bin);
	}
}

sub sub_exists {
	no strict 'refs';
	return defined &{$_[0]} ? 1 : 0;
}

sub redis_connect{
	my ($conf, $nodie) = @_;	
	my $rds = length($conf->{redis_auth})>0 ? Redis->new(server => $conf->{redis_host}.':'.$conf->{redis_port}, password => $conf->{redis_auth}) : Redis->new(server => $conf->{redis_host}.':'.$conf->{redis_port});
	die('Could not establish connection to redis') if(!$nodie && !$rds->ping);
	return $rds;
}

sub op_rkeys {
	my ($pattern, $code, $redis, $params) = @_;
	my ($n, $i, $c, @buffer, @acc);
	
	@buffer = @{[$redis->keys($params->{conf}->{redis_key_prefix}.$pattern)]};

	$n = int(@buffer + 0);
	for($i=0; $i<$n; $i+=4){
		$c = -1;
		map { push @acc, $code->($buffer[$i + ++$c], $_, $redis, $params) } @{$redis->mget( grep defined, @{[@buffer[$i..($i+3)]]} )};
	}
	return @acc;
}

sub op_batch {
	my ($buffer, $code, $params) = @_;
	my ($n, $i, $c, @acc);
	
	$n = int(@$buffer + 0);
	for($i=0; $i<$n; $i+=4){
		$c = -1;
		push @acc, $code->(\@{[ grep defined, @{[@$buffer[$i..($i+3)]]} ]}, $params);
	}
	return @acc;
}

sub _tr_safe_ascii {
	grep tr/\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\xff//d, @_;
	return @_ == 1 ? $_[0] : @_;
}

sub sanitize {
	my ($var, $re, $def) = @_;
	$def = '' if (!defined $def);
	$var =~ tr/\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\xff//d;
	return $var =~ $re ? $1 : ($def ? sanitize($def, $re) : '');
}

sub iptables_safe_cmd {
	my ($args, $conf, $redis) = @_;
	$args = ($conf->{flock_iptables_bin} && $args !~ $conf->{re}->{iptables_passive}) ?  $conf->{flock_iptables_bin}.' '.$args .'"' : $conf->{iptables_bin}.' '.$args;
	inform($args);	
	return $args =~ ($args !~ $conf->{re}->{martian_ip} && $conf->{re}->{iptables_arg}) ? $1 : 'true';
}

sub clean_rules {	
	system('('. join(' || true) && (', @{$_[0]}) .' || true)');
	inform('Cleaned up rules');
}

sub clean_notifications {
	my ($redis, $params) = @_;
	op_rkeys(';warning-*', \&clean_notifications_op, $redis, $params);
}

sub notify_blacklist {
	my ($redis, $params) = @_;
	return if ($params->{conf}->{admin_email} !~ $params->{conf}->{re}->{envelope});
	$params->{admin_email_address} = $1.'@'.$2; 
	op_rkeys(';warning0-*', \&notify_blacklist_op, $redis, $params);
}

sub refresh_iptables {
	my ($redis, $params) = @_;
	$params->{iptables} = '' if(!$params->{iptables});
	op_rkeys(';expires-*', \&refresh_iptables_op, $redis, $params);
}

sub notify_blacklist_op {
	my ($k, $v, $redis, $params) = @_;
	my ($re, %var, $msg, $message);

	$re = $params->{conf}->{re};
	%var = (user => '', domain => '', email => '', ip => '', recipient => '', admin => $params->{admin_email_address});

	$redis->del($k);
	$k =~ s/$re->{subkey}/;warning-/;
	return if($redis->exists($k));
	$redis->set($k => time());

	($v, $var{recipient}) = split("\n", $v);
	if($v =~ $re->{ip} && $k =~ $re->{emailfromkey}){
		$var{user} = decode_base64($1);
		$var{domain} = $2;		
		$var{ip} = $v;		
	}elsif($k =~ $re->{ipfromkey}){
		$var{ip} = $1.$2;
		return if($v !~ $re->{email});
		$var{user} = decode_base64($1);
		$var{domain} = $2;

	}else{
		return;
	}
	$var{email} = $var{user}.'@'.$var{domain};
	$message = $params->{conf}->{admin_message};
	$message =~ s/$re->{admintpl}/$var{lc($1)}/g;

	$msg = MIME::Lite->new(
		'From'		=> $params->{conf}->{admin_email},
		'To'		=> $var{email},
		'Subject'	=> 'Delivery Failure Notification: blocked',
		'Type'		=> 'text/plain',
		'Data'		=> $message,
	);
	$msg->send;
}

sub clean_notifications_op {
	my ($k, $v, $redis, $params) = @_;
	$v = int($v) + 2592000;
	return if ($v > time());
	$redis->del($k);
}

sub refresh_iptables_op {
	my ($k, $v, $redis, $params) = @_;
	my ($re, $t, $ip, $cidr, $nm);

	$re = $params->{conf}->{re};

	$t = time();
	return if ( $t > int($v) || $k =~ $re->{martian_ip} || $k !~ $re->{ipfromkey});

	$ip = $1.$2;

	return if($params->{iptables} =~ /[^0-9]\Q$ip\E[^0-9]/sm);
	$nm = $ip =~ $re->{colon} ? 128 : 32;
	$cidr = $redis->get($params->{conf}->{redis_key_prefix}.';network-'.$ip) || $nm;

	$ip = sanitize($ip, $re->{ip}, '');
	system(iptables_safe_cmd('-t filter -I '.$params->{conf}->{filter_name}.' -i eth+ -s '.$ip.'/'.sanitize($cidr, $re->{integer}, $nm).' -j DROP -m comment --comment \'expires='.sanitize($v, $re->{integer}, $t+864000).'\'', $params->{conf})) if($ip);
}

# Thanks to the authors of Net::IP: Manuel Valente, Monica Cortes Sack, 
# and Lee Wilmot for the implementation concepts behind expand_ipv6()
sub expand_ipv6 {
	my $addr = shift;
	my ($a, $b, $c, $i, @d, @ip);

	$addr =~ s/::/: :/g;
	@ip = split('\:', $addr);

	$c = $a = int(@ip + 0);
	for($i=-1;++$i<$a;){
		if(index($ip[$i], '.')!=-1){
			$b = unpack('B32', pack('C4C4C4C4', split('\.', $ip[$i])));
			$ip[$i] = substr(join(':', unpack('H4H4H4H4H4H4H4H4', pack('B128', '0' x (128 - length($b)) . $b))), -9);
			++$c;
			next;
		}
		$ip[$i] = ('0' x (4 - length($ip[$i]))) . $ip[$i];
	}

	@d = ('0000','0000','0000','0000','0000','0000','0000','0000');
	
	return join(':', (map{ $_ eq '000 ' ?  join(':', @d[0 .. (8 - $c)]) : lc($_) } @ip));
}	

sub compile_regex {
	# Although SA preprocesses much of the data captured, this should be tightened
	return (
		envelope			=> qr/(?:^|(?:[^<]*[<]))([^<>\@]+)\@([^<>\@]+)(?:[>]|$)/,
		spaces				=> qr/[\r\n\t ]+/,
		trim				=> qr/(?:^['",\r\n\t ]+)|(?:['",\r\n\t ]+$)/,
		email				=> qr/^(.*?)\@(.*?)$/,
		n_domainchars			=> qr/[^0-9.\-a-zA-Z]/,
		n_redischars			=> qr/[^0-9.,\@a-z_\-+\/=]/i,
		integer				=> qr/^([0-9]+)$/,
		colon				=> qr/\:/,		
		iptables_passive		=> qr/^[ \t]*-L/,
		iptables_arg			=> qr/^([ -;=A-_a-~]+)$/,
		record				=> qr/^([0-9.]+),([0-9.]+),([0-9.]+),([0-9.]+)(?:(?:,(.*))|$)/,
		subkey				=> qr/;[a-zA-Z0-9]+\-/,
		ip				=> qr/^(?:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|(?:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}))$/i,
		ipn				=> qr/^((?:(?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|(?:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}))(?:\/[0-9]+)?)$/i,
		ipfromkey			=> qr/(?:^|-)((?:[0-9]+\.[0-9]+\.[0-9]+\.)|(?:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{4}\:[0-9a-f]{2}))([0-9a-f]+)(?:[^0-9a-f]|$)/i,
		emailfromkey			=> qr/^[^\-]+-([^\@]+)\@([^\@]+)$/,
		admintpl			=> qr/\$((?:user)|(?:domain)|(?:ip)|(?:email)|(?:recipient)|(?:admin))/i,
		expires				=> qr/[^0-9]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]+)?)[^0-9]+0\.0\.0\.0\/0[^0-9]+expires=([0-9]+)[^0-9]/sm,
		time_cycle			=> qr/^([0-9]+)\:([0-9]+)$/,
		param				=> qr/^((?:flock\_iptables\_bin)|(?:iptables\_bin)|(?:filter\_name)|(?:redis\_auth)|(?:redis\_host)|(?:redis\_port)|(?:redis\_key\_prefix)|(?:admin\_email)|(?:admin\_message))=(.*)$/sm,
		#Thanks to Salvador Fandino's Regexp::IPv6 
		rcvd_header			=> qr/from[ \t]+([^ \t]+)[ \t]+\(.*?\[[\t ]*((?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|(?::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))))[ \t]*\]/i,
		martian_ip			=> sub {
				my ($r, @buffer);
				$r = find_bin('route');
				map{ $_=~/^[ ]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ ]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ ]+(?:[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+))[ ]/ && ($2 && ($2 ne '0.0.0.0') && push @buffer, $2) xor ($1 && ($1 ne '0.0.0.0') && push @buffer, sub{ return $_[0].'([0-9]*[0-9])(?(?{int($+)<'.$_[1].' || int($+)>'.($_[1]+$_[2]).';})X)'; }->(substr($1, 0, rindex($1,'.')+1), int(substr($1, rindex($1,'.')+1)), 256-int($3))) } split("\n", `$r -nA inet`);
				map{ $_=~/^[ ]*([0-9a-f\:]+)[^0-9a-f\:]/i && sub { $_[1] =~ /[0-9a-f]\:[0-9a-f]/i && $_[1] !~ /^(?:(?:0000\:)|(?:fc00\:)|(?:fe80\:)|(?:ff00\:)|(?:2001\:0db8\:)|(?:2001\:0010\:)|(?:3ffe\:))/i && (push @{$_[0]}, lc($_[1]).'[a-f0-9]{2}') }->(\@buffer, substr(expand_ipv6($1), 0, -2) ) } split("\n", `$r -nA inet6`);
				$r = '(?:'.join (')|(?:', @buffer).')';
				$r =~ s/\Q.\E/\\./g;
				$r =~ s/([0-9])\:/$1\\:/g;
				use re 'eval';
				#ipv6 needs *some* work
				return qr/(?:^|[^0-9a-f])(?:(?:0000\:)|(?:fc00\:)|(?:fe80\:)|(?:ff00\:)|(?:2001\:0db8\:)|(?:2001\:0010\:)|(?:3ffe\:)|(?:127\.)|(?:192\.168\.)|(?:0\.)|(?:10\.)|(?:100\.64\.)|(?:224\.)|(?:192\.0\.0\.)|(?:169\.254\.)|$r)(?:[^0-9a-f]|$)/i;

			}->()
	);
}

BEGIN {
        %Regex = compile_regex();
        update($1) if(do {local $/; STDIN->blocking(0); <STDIN>; } =~ /^SpamIPFilterUpdate[ ][ ]*(.*)$/ xor STDIN->blocking(1));

	require Mail::SpamAssassin::Plugin; 
	Mail::SpamAssassin::Plugin->import(); 
	require Mail::SpamAssassin::Logger; 
	Mail::SpamAssassin::Logger->import(); 	
	@ISA = qw(Mail::SpamAssassin::Plugin);

}  # ...

sub new {
	my ($class, $mailsa) = @_;

	$class = ref($class) || $class;
	my $self = $class->SUPER::new($mailsa);
	bless ($self, $class);
	$self->{conf} = { 
		iptables_bin				=> '', 
		filter_name				=> 'spamipfilter',
		redis_host				=> '127.0.0.1', 
		redis_port				=> 6379, 
		redis_auth				=> '', 
		redis_key_prefix			=> 'sa_ipf', 
		trigger_score				=> 6, 
		trigger_messages			=> 3, 
		trigger_sensitivity			=> 4,
		average_score_for_rule			=> 7, 
		expire_rule_seconds			=> 43200,
		seconds_to_decay_penalty		=> 300, 
		expires_multiplier_penalty		=> 1.5, 
		cache_decay_days			=> 30,
		verbose					=> 0,
		whitelist				=> '',
		admin_email				=> '',
		admin_message				=> "\nYour message to \$recipient from \$email was blocked and your IP address \$ip blacklisted due to excessive unsolicited bulk email. \n\nTo reinstate your ability to send email to \$recipient, please reply to \$admin using a different off-network email, including the body of this message with a request for reinstatement.",
		common_hosts				=> 'gmail.com, google.com, yahoo.com, hotmail.com, live.com'		
	};
	$self->{mailsa} = $mailsa;
	$self->set_config($mailsa->{conf});
	return $self;
}

sub set_config {
	my ($self, $conf) = @_;
	my (@cmds, $c);
	foreach $c (keys %{$self->{conf}}){
		push(@cmds, {
				'setting' 	=> 'ipfilter_'.$c,
				'default' 	=> $self->{conf}->{$c},
				'type' 		=> $self->{conf}->{$c} =~ /^[0-9]+(?:\.[0-9]+)?$/ ? $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC : $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
			}
		);		
	}

	$conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
	my ($self, $params) = @_;

	my ($c, $v, $redis);
	$self->{conf}->{whitelist} = {};
	foreach $c (keys %{$self->{conf}}){
		if($params->{conf}->{'ipfilter_'.$c}){
			$v = $params->{conf}->{'ipfilter_'.$c};
			$v =~ s/(?:^[\r\n\t ]+)|(?:[\0])|(?:[\r\n\t ]+$)//g;
			if($v =~ /^([0-9]+(?:\.[0-9]+)?)$/){
				$self->{conf}->{$c} = $1 + 0;
			}elsif($c =~ /whitelist$/i && ($v =~ /^(.*?\@[a-zA-Z0-9\-.]+)$/ || $v =~ /^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]*)$/)){
				${$self->{conf}->{whitelist}}{lc($1)} = 1; 		
			}elsif(($c =~ /\_(?:(?:name)|(?:prefix))$/i && $v =~ /^([a-zA-Z0-9_.]+)$/) || ($c =~ /\_((?:message)|(?:email))$/i && $v =~ /^([ -~]+)$/) || $v =~ /^([,-;A-Za-z _\@]+)$/){
				$self->{conf}->{$c} = $1;
			}
		}
	}

	$Verbose = 1 if(int($self->{conf}->{verbose})>0);
	$self->{conf}->{filter_name} = 'spamipfilter' if ($self->{conf}->{filter_name} !~ /^[a-z0-9\-_.]+$/i);
	$self->{conf}->{iptables_bin} = find_bin('iptables') if(length($self->{conf}->{iptables_bin})<1 || !-e $self->{conf}->{iptables_bin});
	$self->{conf}->{flock_iptables_bin} = find_bin('flock') ? find_bin('flock') . ' /var/lock/'.$self->{conf}->{filter_name}.' -c "' . find_bin('iptables') : '';

	$self->{conf}->{maintenance_interval} = 7200;
	$self->{conf}->{maintenance_tasks} = int(86400/$self->{conf}->{maintenance_interval});

	$self->{conf}->{cache_decay_days} = $self->{conf}->{cache_decay_days} + 0.0;
	$self->{conf}->{cache_decay_days} = 1 if(0.2 > $self->{conf}->{cache_decay_days});
	$self->{conf}->{seconds_to_decay_penalty} =  1 if(1 > $self->{conf}->{seconds_to_decay_penalty});
	$self->{conf}->{trigger_messages} =  1 if(1 > $self->{conf}->{trigger_messages});
	$self->{conf}->{average_score_for_rule} =  1 if(0.2 > $self->{conf}->{average_score_for_rule});
	$self->{conf}->{trigger_sensitivity} = 1 if(0.2 > $self->{conf}->{trigger_sensitivity});

	$c = $self->{conf}->{common_hosts};
	$c =~ s/[\r\n\t ]+//g;
	$c =~ s/\Q.\E/\\./g;
	$c = ($c) ? '(?:^|\.)((?:'.join(')|(?:', split(',', lc($c))).'))(?:[^a-z]|$)' : '^$';
	$Regex{common_hosts} = qr/$c/i;	

	$self->{conf}->{re} = \%Regex;

	lock_hashref($self->{conf});

	debug('[finish_parsing_end] configuration ' .join(', ', map{ $_ .'='. $self->{conf}->{$_}} keys %{$self->{conf}}));

	system('('.join(' || true) && (', (map{ iptables_safe_cmd($_.' '.$self->{conf}->{filter_name}, $self->{conf}) } ('-F', '-N', '-D INPUT -p tcp -j', '-I INPUT -p tcp -j'))).' || true)');

	open(FILE, '+>/etc/cron.d/'.$self->{conf}->{filter_name}) || die 'Could not create /etc/cron.d/'.$self->{conf}->{filter_name}." $!\n";
	print FILE '*/15 * * * * root '.find_bin('echo')." 'SpamIPFilterUpdate ".encode_base64('iptables_bin='.$self->{conf}->{iptables_bin}.'&flock_iptables_bin='.$self->{conf}->{flock_iptables_bin}.'&filter_name='.$self->{conf}->{filter_name}.'&redis_auth='.$self->{conf}->{redis_auth}.'&redis_host='.$self->{conf}->{redis_host}.'&redis_port='.$self->{conf}->{redis_port}.'&redis_key_prefix='.$self->{conf}->{redis_key_prefix}.'&admin_email='.$self->{conf}->{admin_email}.'&admin_message='.$self->{conf}->{admin_message}, '')."' | $^X '-MMail::SpamAssassin::Contrib::Plugin::IPFilter' > /dev/null 2>&1\n";
	close(FILE);
	system('/etc/rc.d/init.d/crond reload') if (-e '/etc/rc.d/init.d/crond');
	$self->inhibit_further_callbacks();
	return 1;
}

sub cidr_2 {
	my (@octet, $ipv6) = @_;
	my $cidr = $ipv6 ? 128 : 32;
	while(0!=($octet[0] ^ $octet[1])){
		$octet[0] = $octet[0] >> 1;
		$octet[1] = $octet[1] >> 1;
		--$cidr;
	}
	return $cidr;
}

sub consolidate_network {
	my ($redis, $params) = @_;
	my (%var, $cidr, $pre, $conf);

	$conf = $params->{conf};

	$pre = $params->{ip}.$params->{host};
	
	$params->{cidr}  = 32;
	$var{$pre} = int($params->{host});	
	if($params->{ipv6}){
		$params->{cidr}  = 128;
		$var{$pre} = hex($params->{host});
	}

	map{$_=~$conf->{re}->{ipfromkey} && ($var{$1.$2} = ($params->{ipv6}) ? hex($2):int($2))} @{[$redis->keys($conf->{redis_key_prefix}.'-'.$params->{ip}.'*')]};
	$cidr = int( cidr_2(  @var{@{[sort { $var{$a} <=> $var{$b} } keys(%var)]}[0,-1]}, $params->{ipv6} ));
	$params->{host} = network_octet($params->{host}, $cidr, $params->{ipv6});
	$params->{network} = int($redis->get($conf->{redis_key_prefix}.';network-'.$params->{ip}.$params->{host}) || $params->{cidr});

	#an edge case may exist due to concurrency where multiple IPs within the same network overwrite one another
	if($cidr < $params->{cidr}){
		
		$pre = $params->{ip}.$params->{host};

		if($cidr < $params->{network}){
			%var = (def => {%{$params->{def_var}}, expires => 0});
			map{ $var{def} = { avg => 0<($var{def}->{avg}+0.0) ? ($var{def}->{avg} + $_->{avg})/2 : $_->{avg}, total => $var{def}->{total} + $_->{total}, spamhits => $var{def}->{spamhits} + $_->{spamhits}, lastspam => int($var{def}->{lastspam})>int($_->{lastspam}) ? $var{def}->{lastspam} : $_->{lastspam}, expires => int($var{def}->{expires})>int($_->{expires}) ? $var{def}->{expires} : $_->{expires} } } @{[ op_rkeys('-'.$params->{ip}.'*', \&consolidate_network_op, $redis, {def_var => $params->{def_var}, conf => $conf}) ]};

			$redis->set($conf->{redis_key_prefix}.';network-'.$pre => $cidr);			
			$redis->set($conf->{redis_key_prefix}.'-'.$pre => $var{def}->{avg}.','.$var{def}->{total}.','.$var{def}->{spamhits}.','.$var{def}->{lastspam}.','.$params->{sender});
			$redis->set($conf->{redis_key_prefix}.';expires-'.$pre => $var{def}->{expires}) if(int($var{def}->{expires})>0);
		}		
	}
	return $pre;
}

sub refresh_list {
	my ($redis, $params) = @_;
	op_rkeys(';expires-*', \&refresh_list_op, $redis, $params);
}

sub refresh_list_op {
	my ($k, $v, $redis, $params) = @_;

	return if ($v > time());
	$redis->del($k);

	return if($k !~ $params->{conf}->{re}->{emailfromkey});
	$v = decode_base64($1).'@'.$2;
	$params->{mailsa}->remove_address_from_whitelist($v);
	inform('[maintenance child] removed from blacklist: '.$v);
}

sub consolidate_network_op {
	my ($k, $v, $redis, $params) = @_;
	my ($re, %var, $ip);
	
	$re = $params->{conf}->{re};
	%var = $v =~ $re->{record} ? (avg => $1 + 0.0, total => $2 + 0.0, spamhits => int($3), lastspam => int($4), cachehit => 1) : %{$params->{def_var}};
	$var{expires} = 0;
	if($k =~ $re->{ipfromkey}){
		$ip = $1.$2;
		$var{expires} = $redis->get($params->{conf}->{redis_key_prefix}.';expires-'.$ip) || 0;
		$redis->del($params->{conf}->{redis_key_prefix}.';network-'.$ip);
		$redis->del($params->{conf}->{redis_key_prefix}.';expires-'.$ip);
	}
	$redis->del($k);
	return \%var;
}

sub cache_decay_op {
	my ($k, $v, $redis, $params) = @_;
	my ($re, $time, %a);
	
	$time = time();
	$re = $params->{conf}->{re};

	$v =~ s/$re->{spaces}//g;
	return if($v !~ $re->{record});
	
	%a = (avg => $1 + 0.0, total => $2 + 0.0, spamhits => int($3), lastspam => int($4), morf => $5);
	$a{lastspam_delta} = $time - $a{lastspam};
	return if($a{lastspam_delta}<60);
	
	$a{morf} = (exists $a{morf} && length($a{morf}) > 0) ? $a{morf} : '';
	if($params->{cache_decay_secs} < $a{lastspam_delta}){
		$redis->del($k);
		inform('[maintenance child] removed from cache: '.$k.' => '.$v);
		return;
	}
	$a{x} = $a{lastspam_delta}/$params->{cache_decay_secs};
		
	$a{y} = exp(-3.2*$a{x}); 
	$a{total} = nearest(0.01, $a{total} * $a{y});
	$a{spamhits} = ($a{spamhits}>2  && $params->{conf}->{trigger_score}<$a{avg} && ($params->{conf}->{trigger_score} > ($a{total}/$a{spamhits}))) ? $a{spamhits} - 1 : 1;
	$a{avg} = nearest(0.01, $a{total}/$a{spamhits});
	$a{morf} =~ s/$re->{trim}//g;
	$redis->set($k => $a{avg}.','.$a{total}.','.$a{spamhits}.','.$a{lastspam}.','.$a{morf});
	inform('[maintenance child] decay updated cache: '.$k.' => from: '.$v. ' to: '. $a{avg}.','.$a{total}.','.$a{spamhits}.','.$a{lastspam}.','.$a{morf});

}

sub maintenance {
	my ($mailsa, $redis, $conf) = @_;
	my ($last_time_cycle, $last_cycle, $last_time);

	$last_time_cycle = $redis->get($conf->{redis_key_prefix}) || '';

	if($last_time_cycle !~ $conf->{re}->{time_cycle}){
		$last_time = time();
		$last_cycle = 0;
		$redis->set($conf->{redis_key_prefix} => $last_time.':'.$last_cycle);
		$redis->quit;
		debug('[maintenance] initialized '.$last_time.':'.$last_cycle);
		return 0;
	}

	$last_time = int($1);
	$last_cycle = int($2);
	if($conf->{maintenance_interval} > (time() - $last_time)){
		$redis->quit;
		debug('[maintenance] nothing to do yet');
		return 0;
	}

	$last_time = time();
	++$last_cycle;
	$last_cycle = 0 if ($conf->{maintenance_tasks} <= $last_cycle);
	
	select(undef, undef, undef, int(rand(24) + 8)/128);
	if($last_time_cycle ne $redis->get($conf->{redis_key_prefix})){
		$redis->quit;
		inform('[maintenance] possible contention, bailing...');
		return 0;
	}
	$redis->set($conf->{redis_key_prefix} => $last_time.':'.$last_cycle);
	$redis->quit;

	debug('[maintenance] forking child '.$last_time.':'.$last_cycle);

	my $pid = fork();
	if(!defined $pid){
		error('[maintenance] Could not fork maintenance process');
		return 0;
	}

	if($pid){ 
		$SIG{CHLD} = 'IGNORE';
		debug('[maintenance] child forked');
		return 1; #parent returns
	}

	inform('[maintenance child] running');

	close STDIN;
	close STDOUT;

	open STDIN,  '<', '/dev/null' or die $!;
	open STDOUT, '>', '/dev/null' or die $!;

	debug('[maintenance child] detached');
		
	my $_redis = redis_connect($conf);

	refresh_list($_redis, {mailsa => $mailsa, conf => $conf});
	
	if($last_cycle != 0){
		$_redis->quit;
		exit;
	}

	inform('[maintenance child] primary cycle');

	op_rkeys('-*', \&cache_decay_op, $_redis, { conf => $conf, cache_decay_secs => $conf->{cache_decay_days}*86400 });

	$_redis->quit;
	debug('[maintenance child] done');
	exit(0);
}

sub check_end {
	my ($self, $params) = @_; 
	my ($msg, $conf, $msg_score, $spam_score, $ham_trigger, $spam_trigger, $redis, $key, $pre, $re, %var, %def_var, %sender, %whitelist);
	%def_var = (avg => 0, total => 0, spamhits => 0, lastspam => 0);

	$msg = $params->{permsgstatus};
	$conf = $self->{conf}; 
	$re = $self->{conf}->{re};	
	%whitelist = %{$self->{conf}->{whitelist}};

	$msg_score = $msg->get_score() + 0.0;
	$spam_score = $msg->get_required_score() + 0.0;
	$spam_trigger = $spam_score + 1;
	$ham_trigger = $spam_score - 1;
	
	if($conf->{trigger_score} > $spam_score){
		$spam_trigger = $conf->{trigger_score};
		$ham_trigger = $spam_score - ($conf->{trigger_score} - $spam_score);
	}
	
	debug('[check_end] processing message with score='.$msg_score.' (spam_score:'.$spam_score.', spam_trigger:'.$spam_trigger.', ham_trigger:'.$ham_trigger.')');
	return 0 if($msg_score > $ham_trigger && $msg_score < $spam_trigger);
	
	%sender = (ip => '', host => '', ipv6 => 0, to => '', envelope => '', from => '', fkey => '', user => '',  domain => '', is_common_domain => 0, extra => '');

	$pre = substr($msg->get('ALL-INTERNAL'), 0, 4096); 
	if($pre !~ $re->{rcvd_header}){
		$pre = substr($msg->get('Received'), 0, 4096); 	
		debug('[check_end] Received header may be external');	
		$pre =~ $re->{rcvd_header};
	}
	
	if(($1) && ($2)){
		$sender{host} = lc($1);
		$sender{ip} = $2;
		debug('[check_end] Received header: '._tr_safe_ascii($pre));
	}else{
		
		inform('[check_end] Could not match rcvd host/ip in: '._tr_safe_ascii($pre));		
		while ( $pre = pop @{$msg->{relays_untrusted}} ){
			if($pre->{ip} && !$pre->{ip_private}){
				$sender{ip} = $pre->{ip};
				$sender{host} = 'unknown';
				last;
			}
		}
		if (!$sender{ip}){
			debug('[check_end] Could not determine IP');
			return 0;
		}
	}

	_tr_safe_ascii($sender{ip}, $sender{host});
	if($sender{ip} =~ $re->{colon}){
		$sender{ipv6}= 1;
		$sender{ip} = expand_ipv6($sender{ip});
	}

	if ($sender{ip} !~ $re->{ip}){
		debug('[check_end] Could not determine IP '.$sender{ip});
		return 0;
	}		

	$sender{to} = lc($msg->get('To:addr') || '');
	$sender{to} =~ s/$re->{spaces}//g;

	$sender{envelope} = $msg->get('EnvelopeFrom:addr') || '';
	$sender{from} = substr($sender{envelope} =~ $re->{envelope} ? lc($1.'@'.$2) : lc($msg->get('From:addr') || ''), 0, 512);
	$sender{from} =~ s/$re->{spaces}//g;

	_tr_safe_ascii($sender{from}, $sender{to});

	if($sender{from} =~ $re->{email} && ($1) && ($2)){		
		$sender{user} = $1;
		$sender{domain} = $2;
		$sender{domain} =~ s/$re->{n_domainchars}//g;
		$sender{fkey} = encode_base64($sender{user}, '').'@'.$sender{domain};
		$sender{extra} = $sender{fkey};
	}

	inform('[check_end] user/domain/ip/host: '.$sender{user}.'/'.$sender{domain}.'/'.$sender{ip}.'/'.$sender{host});
	
	$key = $conf->{redis_key_prefix}.'-'.$sender{ip};	
		
	if($sender{host} =~ $re->{common_hosts}){
		$sender{is_common_domain} = 1;
		$sender{domain} = $1 if(!$sender{envelope});
		debug('[check_end] domain is common');
		if(!$sender{user}){
			$sender{from} = 'no user specified' if (!$sender{from});
			error('[check_end] Could not find envelope user from: '.$sender{domain}.' ('.$sender{from}.')');
			return 0;
		}

		$sender{from} = $sender{user}.'@'.$sender{domain};
		if(exists $whitelist{'@'.$sender{domain}} || exists $whitelist{$sender{from}}){
			debug('[check_end] done '.$sender{from}.' whitelisted');
			return 1;
		}
		$sender{extra} = $sender{ip};
		$sender{fkey} = encode_base64($sender{user}, '').'@'.$sender{domain};
		$key = $conf->{redis_key_prefix}.'-'.$sender{fkey};
	}

	inform('[check_end] key: '.$key);

	if(exists $whitelist{$sender{ip}}){
		debug('[check_end] done '.$sender{ip}.' whitelisted');
		return 1;
	}

	if(!($redis = redis_connect($conf, 1))){
		error('[check_end] Could not establish connection to redis');	
		return 0;		
	}

	$sender{host} = $sender{ip};
	if($key=~$re->{ipfromkey}){
		$sender{ip} = consolidate_network($redis, {ip => $1, host => $2, sender => $sender{fkey}, ipv6 => $sender{ipv6}, conf => $conf, def_var => \%def_var}); 
		if(exists $whitelist{$sender{ip}}){
			debug('[check_end] done '.$sender{ip}.' whitelisted');
			return 1;
		}
		$key = $conf->{redis_key_prefix}.'-'.$sender{ip};		
	}

	$pre = $redis->get($key) || '';
	$pre =~ s/$re->{n_redischars}//g;
	debug('[check_end] cached record: '.$pre);
	%var = $pre =~ $re->{record} ? (avg => $1 + 0.0, total => $2 + 0.0, spamhits => int($3), lastspam => int($4), cachehit => 1) : %def_var;
	if($msg_score < $ham_trigger){
		debug('[check_end] processing as ham');
		if(exists $var{cachehit}){
			$var{total} = $var{total} - ($var{avg} + ($spam_score - $msg_score));
			--$var{spamhits};
			if($var{total}<1){				
				%var = (%def_var, lastspam => $var{lastspam});				
			}else{
				$var{spamhits} = 1 if($var{spamhits}<1);
				$var{avg} = nearest(0.01, $var{total}/$var{spamhits});
				$var{total} = nearest(0.01, $var{total});
			}
			
			$redis->set($key => $var{avg}.','.$var{total}.','.$var{spamhits}.','.$var{lastspam}.','.$sender{extra});
			inform('[check_end:ham] updated cache: '.$key.' => from: '.$pre.' to: '.$var{avg}.','.$var{total}.','.$var{spamhits}.','.$var{lastspam}.','.$sender{extra});
		}

		maintenance($self->{mailsa}, $redis, $conf);
		debug('[check_end] done');
		return 1;
	}

	debug('[check_end] processing as spam');
	$var{lastspam_delta} = time() - $var{lastspam};

	$var{w} =  $var{spamhits} < 1 ?  $conf->{trigger_sensitivity} : $conf->{trigger_sensitivity}/$var{spamhits};
	$var{x} = $conf->{seconds_to_decay_penalty}>$var{lastspam_delta} ? 0 : $var{lastspam_delta}/$conf->{seconds_to_decay_penalty};
	$var{y} = 1 + exp(-1*$var{x}/10) + exp(-3.2*$var{w});

	debug('[check_end] penalty '.$var{y});

	++$var{spamhits};
	$var{spamhits} = 1 if($var{spamhits}<1);

	$var{score} = $msg_score * $var{y};
	$var{total} = nearest(0.01, $var{total} + $var{score});
	$var{avg} = nearest(0.01, $var{total}/$var{spamhits}); 
	$var{lastspam} = time();

	$redis->set($key => $var{avg}.','.$var{total}.','.$var{spamhits}.','.$var{lastspam}.','.$sender{extra});
	inform('[check_end:spam]  updated cache: '.$key.' => from: '.$pre.' to: '.$var{avg}.','.$var{total}.','.$var{spamhits}.','.$var{lastspam}.','.$sender{extra});

	if($var{avg} >= $conf->{average_score_for_rule} && $var{spamhits} >= $conf->{trigger_messages}){
		
		$var{z} = $var{y} * ($var{score}/$conf->{average_score_for_rule});	
		$var{z} = $conf->{expires_multiplier_penalty}*(1 + $var{z}) if($var{z} >= $conf->{expires_multiplier_penalty});
		debug('[check_end] expires penalty '.$var{z});

		$var{expires} = $var{lastspam} + int($conf->{expire_rule_seconds} * $var{z});
		
		if($sender{is_common_domain}){
			$self->{mailsa}->add_address_to_blacklist($sender{from});
			$redis->set($conf->{redis_key_prefix}.';expires-'.$sender{fkey} => $var{expires});
			$redis->set($conf->{redis_key_prefix}.';warning0-'.$sender{fkey} => $sender{ip}."\n".$sender{to}) if($conf->{admin_email} && !$redis->exists($conf->{redis_key_prefix}.';warning-'.$sender{fkey}));			
		}else{			
			$redis->set($conf->{redis_key_prefix}.';expires-'.$sender{ip} => $var{expires});
			$redis->set($conf->{redis_key_prefix}.';warning0-'.$sender{ip} => $sender{fkey}."\n".$sender{to}) if($conf->{admin_email} && !$redis->exists($conf->{redis_key_prefix}.';warning-'.$sender{ip}));
		}
		inform('[check_end] added to blacklist: '.$sender{from}.' '.$sender{ip});
	}

	maintenance($self->{mailsa}, $redis, $conf);
	debug('[check_end] done');
	return 1;

}

sub network_octet {
	# (octet, cidr) = @_
	return $_[2] ? sprintf('%02x', hex($_[0]) & (256 - (1<<(128-$_[1])))) : $_[0] & (256 - (1<<(32-$_[1])));
}


1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Mail::SpamAssassin::Contrib::Plugin::IPFilter - Blocks bad MTA behavior using IPTables and Redis.

=head1 VERSION

0.92

=head1 SYNOPSIS

To try this out, add this or uncomment this line in init.pre:

	LoadPlugin    Mail::SpamAssassin::Contrib::Plugin::IPFilter

I<Configuration defaults>

	filter_name spamipfilter
	iptables_bin $PATH/iptables

	redis_host 127.0.0.1
	redis_port 6379
	redis_auth [password]
	redis_key_prefix spam-ipfilter

	average_score_for_rule  8
	cache_decay_days 5	
	expire_rule_seconds 14400
	expires_multiplier_penalty 1.5	
	seconds_to_decay_penalty 300
	trigger_score 6
	trigger_messages 4
	trigger_sensitivity 4

	common_hosts gmail.com, google.com, yahoo.com, hotmail.com, live.com
	admin_message Your message to $recipient from $email was blocked and your IP address $ip blacklisted 
	   due to excessive unsolicited bulk email. To reinstate your ability to send email to $recipient, 
	   please reply to $admin using a different off-network email, including the body of this message, 
	   with a request for reinstatement.
	verbose 0

=head1 DESCRIPTION

Mail::SpamAssassin::Contrib::Plugin::IPFilter blacklists unsolicited bulk email senders using IPTables and a Redis based cache. It will blacklist the sender IP using the smallest network possible, up to /24, when UCE originates from multiple hosts on the same network. Depending on the diversity and frequency of spam received on a server, it may take a couple of days to become effective. Thereafter, the cache state will decay to prevent spammers from burning IP blocks.

Responsible, well-known email hosts (common_hosts) are given special treatment to avoid blacklisting their networks. UCE originating from common_hosts is blacklisted on a per sender basis using SpamAssassin's AWL. The plugin may be configured to email the blacklisted sender a warning for remediation. A sane IPTables setup and non-volatile Redis configuration are assumed. Additionally, an entry is created in /etc/cron.d/ for required maintenence.

IPV6 support is experimental. Future versions may include a database shared by nodes participating in a system similar to a decaying blockchain.

The following options may be used in site-wide (local.cf) configuration files to customize operation:

=begin html

<b>filter_name</b><br>
 The name of the chain that Mail::SpamAssassin::Contrib::Plugin::IPFilter will create to block spammers. This will also be used as the file name in /etc/cron.d/. [a-zA-Z0-9_.]

<br><br><b>iptables_bin</b><br>
  The path to iptables binary on your system. 

<br><br><b>redis_host</b><br>
 The IPv4 address of your Redis server.

<br><br><b>redis_port</b><br>
 The port that Redis is listening on.

<br><br><b>redis_auth</b><br>
 The Redis password, if any.

<br><br><b>redis_key_prefix</b><br>
 The prefix for Redis keys created and used by Mail::SpamAssassin::Contrib::Plugin::IPFilter. ^[a-zA-Z0-9_.]$

<br><br><b>average_score_for_rule</b><br>
 The average spam score for a host required to trigger a rule after trigger_messages.

<br><br><b>cache_decay_days</b><br>
 After how long will entries in the cache decay, assuming no spam messages are seen. Note that the cache will decay according to: cumulative_spam_score_for_host * exp(-3*lastspam_delta/cache_decay_secs)

<br><br><b>expire_rule_seconds</b><br>
 After how long will a block rule expire.

<br><br><b>expires_multiplier_penalty</b><br>
 A factor used to penalize hosts with longer rule expiration based on the spam of score of the message resulting in a rule, relative to the average spam score required to set the rule. 

<br><br><b>seconds_to_decay_penalty</b><br>
 A frequency indicator used to tune penalization for a given host based on how many spam messages were seen for that host over a time period. PF = exp((-1/10 * lastspam_delta/seconds_to_decay_penalty))

<br><br><b>trigger_score</b><br>
 The score for which Mail::SpamAssassin::Contrib::Plugin::IPFilter will process a spam message. This should be greater than the SpamAssassin required_score.

<br><br><b>trigger_messages</b><br>
 The minimum number of spam messages from a given host before a rule is triggered. 

<br><br><b>trigger_sensitivity</b><br>
 A quantity indicator used to tune penalization for a given host based on how many spam messages were seen for that host. PF = exp(-3*trigger_sensitivity/spamhits)

<br><br><b>common_hosts</b><br>
 Hosts which should not be blacklisted via IPTables rule, and fall back to SpamAssassin blacklist.

<br><br><b>admin_email</b><br>
 The email address to send blacklist warnings from. If left unconfigured, no warnings will be sent.

<br><br><b>admin_message</b><br>
 The warning message that will be sent. Paramaters $user, $domain, $ip, $email, $recipient and $admin may be used for templatization.

<br><br><b>whitelist</b><br> 
 Any email address or ip address to whitelist. Email addresses may be specified as foo@example.com or just @example.com to match the whole domain, and IPs may be specified as 1.2.3.4 or just 1.2.3. to match the class C address space.

<br><br><b>verbose</b><br>
 Log additional information via Mail::SpamAssassin::Logger

=end html

=head1 COPYRIGHT

I<Copyright E<copy> 2014 Tamer Rizk, Inficron Inc.>

This is free, open source software, licensed under the L<Revised BSD License|http://opensource.org/licenses/BSD-3-Clause>. Please feel free to use and distribute it accordingly.

=cut

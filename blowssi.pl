#!/usr/bin/perl -w

# -------------------- includes --------------------

# include ircBlowfish
use Crypt::ircBlowfish;

# include everything needed cbc+base64
use Crypt::CBC;
use MIME::Base64;

# include irssi stuff
use Irssi::Irc;
use Irssi;
use vars qw($VERSION %IRSSI);

# i don't trust myself
use strict;

# ----------------- package info  ------------------

# irssi package info
my $VERSION = "0.0.1";
my %IRSSI = (
  authors => 'John "Gothi[c]" Sennesael',
  contact => 'john@adminking.com',
  name => 'blowssi',
  description => 'Fish and mircryption compatible blowfish/cbc encryption',
  license => 'GNU GPL v3',
  url => 'http://linkerror.com/blowssi.cgi'
);

# ----------------- init globals -------------------

# default prefix
my $prefix = '+OK ';
# crypt enabled by default
my $docrypt = 1;
# associative array for channel->key
my %channels;
# get config file name
my $config_file = Irssi::get_irssi_dir()."/blowssi.conf";
# init blowfish object
my $blowfish = new Crypt::ircBlowfish;

# ----------------- subroutines --------------------

# blows up a key so it matches 56 bytes.
sub blowkey
{
  # get params
  my $key = @_[0];
  # keep adding the key to itself until it's larger than 56 bytes.
  while (length($key) < 56)
  {
    $key .= $key;
  }
  # now trunkate it to exactly 56 bytes.
  $key = substr($key,0,56);
  return $key;
}

# loads configuration
sub loadconf
{
  # open config file
  my @conf;
  open (CONF, "<$config_file");
  # if config file does not exist, create it with default settings and exit.
  if (!( -f CONF))
  {
    Irssi::print("\00305> $config_file not found, using default settings.\n");
    Irssi::print("\00305> Creating $config_file with default values.\n\n");
    close(CONF);
    open(CONF,">$config_file");
    close(CONF);
    return 1;
  }
  # otherwise, proceed with reading config.
  @conf=<CONF>;
  close(CONF);
  my $current;
  foreach(@conf)
  {
    $current = $_;
    $current =~ s/\n//g; # remove newline
    if ($current ne '')
    {
      # config syntax is channel:key so split the string and get both.
      my $channel = (split(':',$current,2))[0]; 
      my $key = (split(':',$current,2))[1]; 
      # remove leading/trailing spaces
      $channel =~ s/^\s+//; 
      $channel =~ s/\s+$//; 
      $key =~ s/^\s+//; 
      $key =~ s/\s+$//; 
      # assign into array.
      $channels{$channel} = $key;
      Irssi:print("\00305> Loaded key for channel: $channel");
    }
  }
  Irssi::print("\00314- configuration file loaded.\n");
  return 1;
}

sub saveconf
{
  
  # local declarations
  my ($channel,$key) = "";

  # open config file
  my @conf ;
  open (CONF, ">$config_file");
  
  # error check
  if (!( -f CONF))
  {
    Irssi::print("\00305> Could not load config file: $config_file\n");
    close(CONF);
    return 1;
  }
  
  # write out config
  while ( ($channel,$key) = each(%channels) )
  {
    if ( ($channel) && ($key) )
    {
      print CONF "$channel:$key\n";
    }
  }
  close(CONF);
}

sub delkey
{

  # parse params
  my $channel = @_[0];

  # check user sanity
  if (!$channel)
  {
    Irssi::print("No channel specified. Syntax: /blowdel channel\n");
    return 1;
  }

  # delete from array
  delete ($channels{$channel});

  # save to config
  saveconf();

  # print status
  Irssi::print("Key deleted, and no longer using encryption for $channel\n");

}

# calculates privmsg length.
sub irclen
{
  my ($len,$curchan,$nick,$userhost) = @_;

  # calculate length of "PRIVMSG #blowtest :{blow} 4b7257724a ..." does not exceed
  # it may not exceed 511 bytes
  # result gets handled by caller.

  return ($len + length($curchan) + length("PRIVMSG : ") + length($userhost) + 1 + length($nick) );
}

# turn on blowfish encryption
sub blowon
{
  $docrypt = 1;
  Irssi::print("Blowfish encryption/decryption enabled\n");
}

# turn off blowfish encryption
sub blowoff
{
  $docrypt = 0;
  Irssi::print("Blowfish encryption/decryption disabled\n");
}

# change encryption key
sub setkey
{

  # parse params
  my $param=@_[0];
  my $channel = (split(' ',$param))[0];
  my $key = (split(' ',$param))[1];
  # check user sanity
  if (!$channel)
  {
    Irssi::print("Error: no channel specified. Syntax is /blowkey channel key\n");
    return 1;
  }
  if (!$key)
  {
    Irssi::print("Error: no key specified. Syntax is /blowkey channel key\n");
    return 1;
  }
  $channels{$channel} = $key;
  Irssi::print("Key for $channel set to $key\n");
  saveconf();
}

# used when a line is too long for a regular print
sub enhanced_printing
{
  my ($server,$curchan,$in) = @_;
  # calls the recursing sub recurs ... and 
  my $arref = recurs($server,$curchan,$in);
  # print out.
  printout($arref,$server,$curchan);
}

# This function generates random strings of a given length
sub generate_random_string
{
  my $length_of_randomstring=shift;# the length of 
  # the random string to generate
  my @chars=('a'..'z','A'..'Z','0'..'9','_');
  my $random_string;
  foreach (1..$length_of_randomstring) 
  {
    # rand @chars will generate a random 
    # number between 0 and scalar @chars
    $random_string.=$chars[rand @chars];
  }
  return $random_string;
}

# encrypt text
sub encrypt
{

  # skip if crypt is disabled
  if ($docrypt == 0)
  {
    return 0;
  }

  # get param data
  my ($data, $server, $channel) = @_;
  if (! $channel) { return 1; }
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $line = shift;
  chomp($line);
  if (length($line) == 0)
  {
    return;
  }
  my $nick = $server->{nick};

  # skip if line starts with `
  if (substr($data,0,1) eq '`')
  {
    $data = substr($data,1);
    Irssi::print("debug - data = $data\n");
    $server->command("\^msg -$server->{tag} $curchan $data");
    $server->print($channel->{name}, "<$nick|{NOT ENCRYPTED}> \00311$data",MSGLEVEL_CLIENTCRAP);
    Irssi::signal_stop();
    return;
  }

  # get key
  my $key = $channels{$curchan};
  
  # local declarations
  my $encrypted_message = '';
  my $len=0;       

  # skip if no key
  if (!$key)
  {
    return 0;
  }   

  # check if we're doing cbc or not
  my $method = 'unknown';
  if (substr($key,0,4) eq 'cbc:')
  {
    # encrypt using cbc
    
    $key = substr($key,4); # chop of the "cbc:"
    $key = blowkey($key); #expand to exactly 56 bytes.

    my $randomiv = generate_random_string(8);  
    my $cipher = Crypt::CBC->new( -key => $key,
                               -cipher => 'Blowfish',
                               -header => 'none',
                          -literal_key => 1,
                                   -iv => $randomiv,
                              -padding => 'null'
                             );

    my $cbc = $randomiv . $cipher->encrypt($data);
    $encrypted_message = $prefix . '*' . encode_base64($cbc);
    $method = 'cbc';
  }
  else
  {
    $method = 'ecb';
    # set key
    $blowfish->set_key($key);

    # encrypt using blowfish
    $encrypted_message = $prefix . $blowfish->encrypt($data);  
  }

  # output line
  $server->print($channel->{name}, "<$nick|{$method}> \00311$data",MSGLEVEL_CLIENTCRAP);
  
  # check if line is too long 
  $len = length($encrypted_message);
  if ( irclen($len,$curchan,$server->{nick},$server->{userhost}) > 510)
  {
    enhanced_printing($server,$curchan,$encrypted_message);
  }
  else
  {
    $server->command("\^msg -$server->{tag} $curchan $encrypted_message");
  }
  Irssi::signal_stop();
  return 1;
}

# decrypt text
sub decrypt
{

  # skip if crypt is disabled.
  if ($docrypt == 0)
  {
    return 0;
  }

  # get param data
  my ($server,$data,$nick,$address) = @_;
  my ($channel,$text,$msgline,$msgnick,$curchan,$curserv);
  if ( ! defined($address) ) # dcc chat
  {
    $msgline = $data;
    $curserv = $server->{server}->{address};
    $channel = $curchan = "=".$nick;
    $msgnick = $nick;
    $server  = $server->{server};
  } else
  {
    ($channel, $text) = $data =~ /^(\S*)\s:(.*)/;
    $msgline = $text;
    $msgnick = $server->{nick};
    $curchan = $channel;
    $curserv = $server->{address};
  }

  # local declarations
  my $result = '';
  my $key = $channels{$channel};
  my $method = '';

  # skip if there's no key for channel
  if (!$key) 
  {
    return 0;
  }

  # check for prefix
  my $ppfix = substr $msgline, 0, length($prefix);
  if ($ppfix eq $prefix)
  { 
    # remove prefix
    $msgline = substr $msgline,length($prefix);
  }
  else
  {
    # skip if message is not encrypted
    return 0;
  }

  if (substr($key,0,4) eq 'cbc:')
  {
    # decrypt with cbc
    
    $key = substr($key,4); # get rid of "cbc:" from key
    
    # remove the asterisk from data
    $msgline = substr($msgline,1);

    # base64 decode the rest
    $msgline = decode_base64($msgline);

    # get the IV (first 8 bytes) and remove it from data;
    my $randomiv = substr($msgline,0,8);
    $msgline = substr($msgline,8);
    
    my $cipher = Crypt::CBC->new( -key => blowkey($key),
                               -cipher => 'Blowfish',
                               -header => 'none',
                          -literal_key => 1,
                              -padding => 'null',
                                   -iv => $randomiv
                                );
    $result = $cipher->decrypt($msgline);
    $method = 'cbc';
  }
  else
  {
    # decrypt with blowfish
    $method = 'ecb';
    $blowfish->set_key($key);
    $result = $blowfish->decrypt($msgline);
  }

  # output result
  if (length($result))
  {
    $server->print($channel, "<$nick|{$method}> \00311$result", MSGLEVEL_CLIENTCRAP);
    Irssi::signal_stop();
    return 1;
  }
  else
  {
    return 0;
  }
}

# dcc proxy function because params for dcc messages are different
sub dcc
{
  my ($server, $data) = @_ ;
  encrypt($server,$data,$server->{nick},undef);
}

# ----------------- main program -------------------

# load config
loadconf();

# inform user of stuff
Irssi::print("blowssi script $VERSION loaded\n");

# register irssi commands
Irssi::command_bind("blowon","blowon");
Irssi::command_bind("blowoff","blowoff");
Irssi::command_bind("blowkey","setkey");
Irssi::command_bind("blowdel","delkey");
# register irssi signals
Irssi::signal_add("event privmsg","decrypt");
Irssi::signal_add("dcc chat message","dcc");
Irssi::signal_add("send text","encrypt");


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
my $VERSION = "0.1.0";
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
my @prefixes = ('+OK ','mcps ');
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
  my $orig_key = $key;
  # don't need to do anything if it's already big enough.
  if (length($key) >= 8)
  {
    return $key;
  }
  # keep adding the key to itself until it's larger than 8 bytes.
  while (length($key) < 8)
  {
    $key .= $key;
  }
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
  my $channel = (split(' ',$param,2))[0];
  my $key = (split(' ',$param,2))[1];
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

  # Uncomment to debug signals.
  #
  #my $n = 0;
  #foreach (@_)
  #{
  #  print "Debug encrypt: $n : $_"; 
  #  $n++;
  #}

  # Skip if crypt is disabled.
  if ($docrypt == 0)
  {
    return 0;
  }
  
  # Holds parameters passed to function.
  my @params = @_;

  # Type of signal received. 
  my $event_type = @params[0];
  
  # Will hold Irssi server object.
  my $server;

  # Will hold channel name.
  my $channel = '';

  # Will hold message text.
  my $message = '';

  # Extract params for send_text events.
  if ($event_type eq 'send_text')
  {

    # Get message text.
    $message = @params[1];
    chomp($message);

    # Get server object.
    $server = @params[2];

    # Get channel or nickname.    
    my $channel_object = @params[3];
    $channel = $channel_object->{name};

  }
  # Extract params for send_command events.
  elsif ($event_type eq 'send_command')
  { 
    # Get command the user entered (eg: /me says hi)
    my $command_line = @params[1];

    # Get server object.
    $server = @params[2];

    # Get channel object.
    my $channel_object = @params[3];

    # We handle /me and /action commands, which will
    # be the first word in the $command_line string.
    my $command = (split(' ',$command_line))[0];

    # Target channel is the first param to the /action command.
    # Message to send is the 3rd param to /action, 2nd to /me.
    # Otherwise, for /me just get the channel from the active window.
    if ($command =~ m/\/action/i)
    {
      $channel = (split(' ',$command_line,2))[1];
      $message = (split(' ',$command_line,3))[2];
      print "ACTION: $channel | $message";
    }
    elsif ($command =~ m/\/me/i)
    {
      $channel = $channel_object->{name};
      $message = (split(' ',$command_line,2))[1];
      print "ME: $channel | $message";
    }
    else
    {
      # The only send_command's we handle here are /me and /action...
      return 0;
    }    
  }
  # Extract params for everything else.
  else
  {

    # Get server object.
    $server = @params[1];

    # Get message text.
    $message = @params[2];
    chomp($message);

    # Get channel or nickname target
    $channel = @params[3];

  }
 
  # Get the current active server address.
  my $current_server = $server->{address};

  # Get the user's nickname (own nickname).
  my $own_nick = $server->{nick};

  # If there's no text to encrypt, then don't try.
  if (length($message) == 0)
  {
    return;
  }

  # skip if line starts with `
  if (substr($message,0,1) eq '`')
  {
    $message = substr($message,1);
    if ($event_type eq 'send_command')
    {
      $server->command("\^ACTION -$server->{tag} $channel $message");
      $server->print($channel, " ** $own_nick(NOT ENCRYPTED) \00311$message",MSGLEVEL_CLIENTCRAP);    
    }
    else
    {
      $server->command("\^msg -$server->{tag} $channel $message");
      $server->print($channel, "<$own_nick|{NOT ENCRYPTED}> \00311$message",MSGLEVEL_CLIENTCRAP);
    }
    Irssi::signal_stop();
    return 1;
  }

  # get key
  my $key = $channels{$channel};
  
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
    $key = blowkey($key); #expand >= 8 bytes.
    my $randomiv = generate_random_string(8);  
    my $cipher = Crypt::CBC->new( -key => $key,
                               -cipher => 'Blowfish',
                               -header => 'none',
                          -literal_key => 0,
                                   -iv => $randomiv,
                              -padding => 'null',
                              -keysize => 56
                             );
    $cipher->{literal_key} = 1; # hack around Crypt:CBC limitation/bug
    
    # my $cbc = $cipher->encrypt($randomiv . $message);
    my $cbc = $randomiv . $cipher->encrypt($message);
 
    # uncomment below for debug
    #Irssi::print("randomiv = $randomiv \n \$cbc = $cbc\n");
    
    $encrypted_message = $prefixes[0] . '*' . encode_base64($cbc);
    $method = 'cbc';
  }
  else
  {
    $method = 'ecb';
    # set key
    $blowfish->set_key($key);

    # encrypt using blowfish
    $encrypted_message = $prefixes[0] . $blowfish->encrypt($message);  
  }

  # output line
  if ($event_type eq 'send_command')
  {
    $server->print($channel, "** $own_nick($method) \00311$message",MSGLEVEL_CLIENTCRAP);
    $server->command("\^ACTION -$server->{tag} $channel $encrypted_message");
  }
  else
  {
    $server->print($channel, "<$own_nick|{$method}> \00311$message",MSGLEVEL_CLIENTCRAP); 
    $server->command("\^msg -$server->{tag} $channel $encrypted_message");
  }
  Irssi::signal_stop();
  return 1;
}

# decrypt text
sub decrypt
{
  
  # Uncomment to debug signals.
  #
  #my $n = 0;
  #foreach (@_)
  #{
  #  print "DEBUG decrypt: $n : $_"; 
  #  $n++;
  #}

  # Skip if crypt is disabled.
  if ($docrypt == 0)
  {
    return 0;
  }

  # Holds parameters passed to function.
  my @params = @_;

  # Type of signal received. 
  my $event_type = @params[0];
  
  # Irssi server object.
  my $server = @params[1];

  # Don't decrypt own text.
  if ( $event_type =~ /own/ )
  {
    return 0;
  }

  # Get message text, nickname of other party, hotmask of other party.
  my $message = @params[2];
  my $nick = @params[3];
  my $hotmask = @params[4];

  # Get channel.
  my $channel = @params[5];
  
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
  my $found_prefix = 0;
  foreach my $prefix (@prefixes)
  {
    my $ppfix = substr $message, 0, length($prefix);
    if ($ppfix eq $prefix)
    { 
      # remove prefix
      $message = substr $message,length($prefix);
      $found_prefix = 1;
      last;
    }
  }

  # skip encryption if the message isn't prefixed with an encryption trigger.
  if ($found_prefix == 0)
  {
    return 0;
  }

  # detect encryption type...
  if (substr($key,0,4) eq 'cbc:')
  {
    # decrypt with cbc    
    $key = substr($key,4); # get rid of "cbc:" from key
    
    # remove the asterisk from data
    $message = substr($message,1);

    # base64 decode the rest
    $message = decode_base64($message);

    # get the IV (first 8 bytes) and remove it from data;
    my $randomiv = substr($message,0,8);
    $message = substr($message,8);
  
    # make sure key > 8 bytes.
    $key = blowkey($key);
  
    my $cipher = Crypt::CBC->new( -key => $key,
                               -cipher => 'Blowfish',
                               -header => 'none',
                          -literal_key => 0,
                              -padding => 'null',
                                   -iv => $randomiv
                                );
    $cipher->{literal_key} = 1; # hack around Crypt::CBC limitation/bug
    $result = $cipher->decrypt($message);
    $method = 'cbc';
  }
  else
  {
    # decrypt with blowfish
    $method = 'ecb';
    $blowfish->set_key($key);
    $result = $blowfish->decrypt($message);
  }

  # output result
  if (length($result))
  { 
    if ($event_type eq 'message_action')
    {
      $server->print($channel, " ** $nick($method) \00311$result", MSGLEVEL_CLIENTCRAP);   
    }
    else
    {
      $server->print($channel, "<$nick|{$method}> \00311$result", MSGLEVEL_CLIENTCRAP);
    }
  }
  else
  {
    return 0;
  }

  Irssi::signal_stop();
  return 1;
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

Irssi::signal_add("send text",sub { encrypt 'send_text' => @_ });
Irssi::signal_add("send command",sub {encrypt 'send_command' => @_});

# register irssi signals
Irssi::signal_add_first{
    'message private' => sub { decrypt 'message_private' => @_ },    
    'message public' =>  sub { decrypt 'message_public' => @_ },    
    'message irc action' => sub { decrypt 'message_action' => @_ },    
    'message irc notice' => sub { decrypt 'message_notice' => @_ },
    'message irc own_notice' => sub { encrypt 'message_own_notice' => @_ },
    'message irc ctcp' => sub { decrypt 'message_ctcp' => @_ },
    'message irc own_ctcp' => sub { encrypt 'message_own_ctcp' => @_} 
  };


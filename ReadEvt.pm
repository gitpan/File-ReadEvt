package File::ReadEvt;

use strict;
use Exporter;
use Carp;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = 0.1;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw(new);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use ReadEvt ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.

# Global variables
my $self;				# self reference
my $MAGIC = 0x654c664c;
my %type = (0x0001 => "EVENTLOG_ERROR_TYPE",
  	        0x0010 => "EVENTLOG_AUDIT_FAILURE",
    	      0x0008 => "EVENTLOG_AUDIT_SUCCESS",
      	    0x0004 => "EVENTLOG_INFORMATION_TYPE",
        	  0x0002 => "EVENTLOG_WARNING_TYPE");

#---------------------------------------------------------------------
# new()
# opens file in binary mode; blesses self, including file handle
#---------------------------------------------------------------------      	    
sub new {
#	my $package = shift;
	$self = {};
	$self->{file} = shift;
	if (open($self->{hFile},"<",$self->{file})) {
		binmode($self->{hFile});
#		return bless($self, $package);
		return bless($self);
	}
	else {
		carp "Could not open ".$self->{file}."\n";
	}
}

#---------------------------------------------------------------------
# gets the offset to the first event record in the file
#---------------------------------------------------------------------
sub getFirstRecordOffset {
	$self = shift;
	my $tag;
	my $i = 0;
	my $num_reads;
	my $record;
	my $start;	
	(1 == $self->{validheader}) ? ($start = 48) : ($start = 0);

	seek($self->{hFile},$start,0);
	foreach my $i (1..10000) {
		read($self->{hFile},$record,4);
#		printf "Contents of record = 0x%x\n",unpack("V",$record);
		if ($MAGIC == unpack("V",$record)) {
			$self->{first_ofs} = ((($i - 2) * 4) + 48);
			$self->{curr_ofs} = $self->{first_ofs};
			return $self->{first_ofs};
		}
		else {
			seek($self->{hFile},48 + ($i * 4),0);
		}
	}
}
#---------------------------------------------------------------------
# locateNextRecord();
# locates the next event record; populates $self->{curr_ofs} with the
# value of the current offset
# Input : Length of previous record, or at least 8 bytes (to get past the
#         current record magic number
# Output: Offset of the beginning of the next record (ie, offset to next 
#         instance of the magic number - 1 DWORD (4 bytes)
#---------------------------------------------------------------------
sub locateNextRecord {
	$self = shift;
# Move cursor
	my $cursor = $_[0] || 0;
	$self->{curr_ofs} += $cursor;
	seek($self->{hFile},$self->{curr_ofs},0);
	foreach my $i (1..1000) {
		read($self->{hFile},$self->{record},4);
		if ($MAGIC == unpack("V",$self->{record})) {
# Once the magic number is located, need to back up one DWORD
			$self->{curr_ofs} -= 4;
			return $i;
		}
		else {
			$self->{curr_ofs} += ($i * 4);
			seek($self->{hFile},$self->{curr_ofs},0);
		}
	}
}

#---------------------------------------------------------------------
# Reads an event record; prints out specific info; returns record length
#---------------------------------------------------------------------
sub readEventRecord {
# This offset is the point within the .evt file where the record
# begins
  $self = shift;
  my %hdr;
	seek($self->{hFile},$self->{curr_ofs},0);
	my $bytes;
	eval {
		$bytes = read($self->{hFile},$self->{record},56);
	};
	if ($@) {
		$self->{error} = $@;
		carp $self->{error};
	}
	
	if ($bytes < 56) {
		$self->{error} = "Total number of bytes read = $bytes";
		return ();
	}
	($hdr{length},$hdr{magic},$hdr{rec_num},$hdr{time_gen},$hdr{time_wrt},
 	$hdr{evt_id},$hdr{evt_type},$hdr{num_str},$hdr{category},$hdr{c_rec},
 	$hdr{str_ofs},$hdr{sid_len}, $hdr{sid_ofs},$hdr{data_len},$hdr{data_ofs}) 
		= unpack("VVVVVvx2vvvx2VVVVVV",$self->{record});
	$hdr{evt_type} = $type{$hdr{evt_type}};
	
	if ($hdr{magic} == $MAGIC) {
			
		my $chars = ($self->{curr_ofs} + $hdr{str_ofs}) - ($self->{curr_ofs} + 56);
		seek($self->{hFile},$self->{curr_ofs} + 56,0);
		read($self->{hFile},$self->{record},$chars);
		($hdr{source},$hdr{computername}) = split(/\00/,_uniToAscii($self->{record}),2);
# Messy hack to clean up computer name
		$hdr{computername} = (split(/\00/,$hdr{computername},2))[0];
		
		if ($hdr{sid_len} > 0) {
			seek($self->{hFile},$self->{curr_ofs} + $hdr{sid_ofs},0);
			read($self->{hFile},$self->{record},$hdr{sid_len});
			$hdr{sid} = _translateBinary($self->{record});
		}
	
		if ($hdr{num_str} > 0) {
			my @list = ();
			$hdr{strings} = "";
			seek($self->{hFile},$self->{curr_ofs} +  $hdr{str_ofs},0);
# Will have issue with negative values if the next condition is true
			if ($hdr{str_ofs} > $hdr{data_ofs}) {
				$self->{error} = "String offset in event record is greater than data offset";
			return undef %hdr;
			}
			read($self->{hFile},$self->{record},$hdr{data_ofs} - $hdr{str_ofs});
			@list = split(//,$self->{record});
			map{$hdr{strings} .= $list[$_] unless ($_%2)} (0..(length($self->{record}) - 1));
		}
# Populate data field, if there is any
		if ($hdr{data_len} > 0) {
			seek($self->{hFile},$self->{curr_ofs} + $hdr{data_ofs},0);
			read($self->{hFile},$self->{record},$hdr{data_len});
			$hdr{data} = _translateBinary($self->{record});
		}
	
		return %hdr;
	}
	else {
		$self->{error} = "Header error - not a magic number";
		return ();
	}
}

#---------------------------------------------------------------------
# parseHeader()
# Parses header information from a .evt file; return a hash
# If the magic number is not found in the proper location, the
# header is deemed invalid
#---------------------------------------------------------------------
sub parseHeader {
	$self = shift;
	my %hdr = ();
	my $tag;
	seek($self->{hFile},0,0);
	eval {
 		my $bytes = read($self->{hFile},$self->{record},48);
 		if (48 == $bytes) {
			($hdr{f_size},$hdr{magic},$hdr{oldestoffset},$hdr{nextoffset},
	    	$hdr{nextID},$hdr{oldestID},$hdr{maxsize},$hdr{retention},$hdr{l_size})   
				= unpack("VVx4x4VVVVVx4VV",$self->{record});
		}	
	};
	if ($@) {
		undef %hdr;
		$self->{error} = $@;
	}		
	if ($hdr{magic} != $MAGIC) {
		undef %hdr;
		$self->{error} = "Magic number not valid";
	}
	$self->{validheader} = 1;
	return %hdr;
}

#---------------------------------------------------------------------
# close()
# close the filehandle
#---------------------------------------------------------------------
sub close {close($self->{hFile});}

#---------------------------------------------------------------------
# _translateBinary()
# Translate binary into a string of hex pairs
#---------------------------------------------------------------------
sub _translateBinary {
	my $str = unpack("H*",$_[0]);
	my $len = length($str);
	my @nstr = split(//,$str,$len);
	my @list = ();
	foreach my $i (0..($len/2)) {
		push(@list,$nstr[$i*2].$nstr[($i*2)+1]);
	}
	return join(' ',@list);
}
#----------------------------------------------------------------
# _uniToAscii()
# Input : Unicode string
# Output: ASCII string
# Removes every other \00 from Unicode strings, returns ASCII string
#----------------------------------------------------------------
sub _uniToAscii {
	my $str = $_[0];
	my $len = length($str);
	my $newlen = $len - 1;
	my @str2;
	my @str1 = split(//,$str,$len);
	foreach my $i (0..($len - 1)) {
		if ($i % 2) {
# In a Unicode string, the odd-numbered elements of the list will be \00
# so just drop them			
		}
		else {
			push(@str2,$str1[$i]);
		}
	}
	return join('',@str2);
}

#----------------------------------------------------------------
# getError()
# returns the error message for the module
#----------------------------------------------------------------
sub getError {return $self->{error};}

#----------------------------------------------------------------
# setCurrOfs()
# Sets the current offset within the file
#----------------------------------------------------------------
sub setCurrOfs {
	$self = shift;
	$self->{curr_ofs} = shift;
}

sub getCurrOfs {
	return $self->{curr_ofs};
}

1;
__END__

=head1 NAME

File::ReadEvt - Perl module to read/parse Windows EventLog files without using the Win32 API

=head1 SYNOPSIS

see example files

=head1 DESCRIPTION

File::ReadEvt is a Perl module that can be used to parse/read an MS Windows Event log file without
using the MS API.  This is useful in instances in which the analysis system is not a Windows system, 
or in which the .evt file cannot be read by the API (reports the file as corrupt).  

=head1 SEE ALSO

EventLogRecord structure
http://msdn.microsoft.com/library/en-us/debug/base/eventlogrecord_str.asp

=head1 AUTHOR

Harlan Carvey, E<lt>keydet89@yahoo.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Harlan Carvey (keydet89@yahoo.com)

This library is free software; you can redistribute it and/or modify
it as you like.  However, please be sure to provide proper credit where
it is due.

=cut

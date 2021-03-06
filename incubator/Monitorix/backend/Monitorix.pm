#!/usr/bin/perl

# i-MSCP - internet Multi Server Control Panel
# Copyright (C) 2010-2014 by internet Multi Server Control Panel
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# @category    i-MSCP
# @package     iMSCP_Plugin
# @subpackage  Monitorix
# @copyright   2010-2014 by i-MSCP | http://i-mscp.net
# @author      Sascha Bay <info@space2place.de>
# @link        http://i-mscp.net i-MSCP Home Site
# @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2

package Plugin::Monitorix;

use strict;
use warnings;

use iMSCP::Debug;
use iMSCP::Dir;
use iMSCP::File;
use iMSCP::Execute;
use iMSCP::Database;

use parent 'Common::SingletonClass';

=head1 DESCRIPTION

 This package provides the backend part for the i-MSCP Monitorix plugin.

=head1 PUBLIC METHODS

=over 4

=item install()

 Process install tasks

 Return int 0 on success, other on failure

=cut

sub install
{
	my $self = $_[0];

	if(! -x '/usr/bin/monitorix') {
		error('Unable to find monitorix daemon. Please take a look at the README.md file.');
		return 1;
	}

	if(! -f '/var/lib/monitorix/www/cgi/monitorix.cgi') {
		error('Unable to find monitorix cgi script. Please check the path: /var/lib/monitorix/www/cgi/monitorix.cgi');
		return 1;
	}

	my $rs = $self->_checkRequirements();
	return $rs if $rs;
}

=item enable()

 Process enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
	my $self = $_[0];

	my $rs = $self->_modifyMonitorixCgiFile('add');
	return $rs if $rs;

	$rs = $self->_modifyMonitorixSystemConfigEnabledGraphics();
	return $rs if $rs;

	$rs = $self->_restartDaemonMonitorix();
	return $rs if $rs;

	$rs = $self->_registerCronjob();
	return $rs if $rs;

	$self->buildMonitorixGraphics();
}

=item disable()

 Process disable tasks

 Return int 0 on success, other on failure

=cut

sub disable
{
	$_[0]->_unregisterCronjob();
}

=item uninstall()

 Process uninstall tasks

 Return int 0 on success, other on failure

=cut

sub uninstall
{
	my $self = $_[0];

	my $rs = $self->_modifyMonitorixCgiFile('remove');
	return $rs if $rs;

	$rs = $self->_modifyMonitorixSystemConfig('remove');
	return $rs if $rs;

	$rs = $self->_restartDaemonMonitorix();
	return $rs if $rs;

	if(-f '/etc/apache2/conf.d/monitorix.old') {
		$rs = $self->_modifyDefaultMonitorixApacheConfig('add');
		return $rs if $rs;

		$rs = $self->_restartDaemonApache();
		return $rs if $rs;
	}

	0;
}

=item buildMonitorixGraphics()

 Build monitorix graphics

 Return int 0 on success, other on failure

=cut

sub buildMonitorixGraphics
{
	my $self = $_[0];

	my $monitorixGraphColor;

	my $rdata = iMSCP::Database->factory()->doQuery(
		'plugin_name', 'SELECT plugin_name, plugin_config FROM plugin WHERE plugin_name = ?', 'Monitorix'
	);

	unless(ref $rdata eq 'HASH') {
		error($rdata);
		return 1;
	}

	require JSON;
	JSON->import();

	my $monitorixConfig = decode_json($rdata->{'Monitorix'}->{'plugin_config'});

	if($monitorixConfig->{'graph_color'}) {
		$monitorixGraphColor = $monitorixConfig->{'graph_color'};
	} else {
		$monitorixGraphColor = 'white';
	}

	for(keys %{$monitorixConfig->{'graph_enabled'}}) {
		if($monitorixConfig->{'graph_enabled'}->{$_} eq 'y') {
			my $rs = $self->_createMonitorixGraphics($_, $monitorixConfig->{'graph_enabled'}->{$_});
			return $rs if $rs;
		}
	}

	$self->_setMonitorixGraphicsPermission();
}

=back

=head1 PRIVATE METHODS

=over 4

=item _createMonitorixGraphics()

 Creates the monitorix pictures

 Return int 0 on success, other on failure

=cut

sub _createMonitorixGraphics
{
	my ($self, $graph, $graphColor) = @_;

	my $monitorixCgiPath = '/var/lib/monitorix/www/cgi/monitorix.cgi';

	my ($stdout, $stderr);
	my $rs = execute(
		"$main::imscpConfig{'CMD_PERL'} $monitorixCgiPath" . ' mode=localhost graph=_' . $graph .
			'1 when=1day color=' . $graphColor . ' silent=imagetag',
		\$stdout,
		\$stderr
	);
	error($stderr) if $stderr && $rs;
	return $rs if $rs;

	$rs = execute(
		"$main::imscpConfig{'CMD_PERL'} $monitorixCgiPath" . ' mode=localhost graph=_' . $graph .
			'1 when=1week color=' . $graphColor . ' silent=imagetag',
		\$stdout,
		\$stderr
	);
	error($stderr) if $stderr && $rs;
	return $rs if $rs;

	$rs = execute(
		"$main::imscpConfig{'CMD_PERL'} $monitorixCgiPath" . ' mode=localhost graph=_' . $graph .
			'1 when=1month color=' . $graphColor . ' silent=imagetag',
		\$stdout,
		\$stderr
	);
	error($stderr) if $stderr && $rs;
	return $rs if $rs;

	$rs = execute(
		"$main::imscpConfig{'CMD_PERL'} $monitorixCgiPath" . ' mode=localhost graph=_' . $graph .
			'1 when=1year color=' . $graphColor . ' silent=imagetag',
		\$stdout,
		\$stderr
	);
	error($stderr) if $stderr && $rs;

	$rs;
}

=item _setMonitorixGraphicsPermission()

 Set the correct file permission of the monitorix pictures

 Return int 0 on success, other on failure

=cut

sub _setMonitorixGraphicsPermission
{
	my $rs = 0;

	my $panelUname =
	my $panelGName =
		$main::imscpConfig{'SYSTEM_USER_PREFIX'} . $main::imscpConfig{'SYSTEM_USER_MIN_UID'};

	my $monitorixImgGraphsDir = $main::imscpConfig{'GUI_ROOT_DIR'} . '/plugins/Monitorix/tmp_graph';

	if(-d $monitorixImgGraphsDir) {
		my @monitorixPictureFiles = iMSCP::Dir->new(
			'dirname' => $monitorixImgGraphsDir, 'fileType' => '.png'
		)->getFiles();

		for(@monitorixPictureFiles) {
			my $file = iMSCP::File->new('filename' => "$monitorixImgGraphsDir/$_");
			
			if($_ !~ /^.*\d+[a-y]?[z]\.\d.*\.png/) { # Remove useless files, only zoom graphics are needed
				$rs = $file->delFile();
				return $rs if $rs;
			} else {
				$rs = $file->owner($panelUname, $panelGName);
				return $rs if $rs;

				$rs = $file->mode(0640);
				return $rs if $rs;
			}
		}
	} else {
		error("Unable to open folder: $monitorixImgGraphsDir");
		$rs = 1;
	}

	$rs;
}

=item _modifyMonitorixSystemConfig()

 Modify Monitorix system config file

 Return int 0 on success, other on failure

=cut

sub _modifyMonitorixSystemConfig
{
	my ($self, $action) = @_;

	my $monitorixSystemConfig = '/etc/monitorix/monitorix.conf';

	if(! -f $monitorixSystemConfig) {
		error("File $monitorixSystemConfig is missing.");
		return 1;
	}

	my $file = iMSCP::File->new('filename' => $monitorixSystemConfig);

	my $fileContent = $file->get();
	unless(defined $fileContent) {
		error('Unable to read $monitorixSystemConfig.');
		return 1;
	}
	
	my $monitorixHttpdConfig = "<httpd_builtin>\n\tenabled = n\n";

	my $monitorixBaseDirConfig = "# Start_BaseDir Added by Plugins::Monitorix\n";
	$monitorixBaseDirConfig .= "base_dir = /var/www/imscp/gui/plugins/Monitorix/\n";
	$monitorixBaseDirConfig .= "# Added by Plugins::Monitorix End_BaseDir\n";

	my $monitorixImgDirConfig = "# Start_ImgDir Added by Plugins::Monitorix\n";
	$monitorixImgDirConfig .= "imgs_dir = tmp_graph/\n";
	$monitorixImgDirConfig .= "# Added by Plugins::Monitorix End_ImgDir\n";
	
	if($action eq 'add') {
		if ($fileContent =~ m%^<httpd_builtin.*enabled = y\n%sgm) {
			$fileContent =~ s%^<httpd_builtin>.*enabled = y\n%$monitorixHttpdConfig%sgm;
		}
		
		if ($fileContent =~ m%^base_dir = /var/lib/monitorix/www/%gm) {
			$fileContent =~ s%^base_dir = /var/lib/monitorix/www/%$monitorixBaseDirConfig%gm;
		}

		if ($fileContent =~ m%^# Start_BaseDir Added by Plugins.*End_BaseDir\n%sgm) {
			$fileContent =~ s%^# Start BaseDir added by Plugins.*End_BaseDir\n%$monitorixBaseDirConfig%sgm;
		}

		if ($fileContent =~ m%^imgs_dir = imgs/%gm) {
			$fileContent =~ s%^imgs_dir = imgs/%$monitorixImgDirConfig%gm;
		}

		if ($fileContent =~ m%^# Start_ImgDir Added by Plugins.*End_ImgDir\n%sgm) {
			$fileContent =~ s%^# Start ImgDir added by Plugins.*End_ImgDir\n%$monitorixImgDirConfig%sgm;
		}
	} elsif($action eq 'remove') {
		$fileContent =~ s%^# Start_BaseDir Added by Plugins.*End_BaseDir\n%base_dir = /var/lib/monitorix/www/%sgm;
		$fileContent =~ s%^# Start_ImgDir Added by Plugins.*End_ImgDir\n%imgs_dir = imgs/%sgm;
	}

	my $rs = $file->set($fileContent);
	return 1 if $rs;

	$file->save();
}

=item _modifyMonitorixSystemConfigEnabledGraphics()

 Modify Monitorix system config file and enables/disables graphics

 Return int 0 on success, other on failure

=cut

sub _modifyMonitorixSystemConfigEnabledGraphics
{
	my $monitorixSystemConfig = '/etc/monitorix/monitorix.conf';

	if(! -f $monitorixSystemConfig) {
		error("File $monitorixSystemConfig is missing.");
		return 1;
	}

	my $file = iMSCP::File->new('filename' => $monitorixSystemConfig);

	my $fileContent = $file->get();
	if(! $fileContent) {
		error('Unable to read $monitorixSystemConfig.');
		return 1;
	}

	my $rdata = iMSCP::Database->factory()->doQuery(
		'plugin_name', 'SELECT plugin_name, plugin_config FROM plugin WHERE plugin_name = ?', 'Monitorix'
	);

	unless(ref $rdata eq 'HASH') {
		error($rdata);
		return 1;
	}

	require JSON;
	JSON->import();

	my $monitorixConfig = decode_json($rdata->{'Monitorix'}->{'plugin_config'});

	for(keys %{$monitorixConfig->{'graph_enabled'}}) {
		$fileContent =~ s/$_(\t\t|\t)= (y|n)/$_$1= $monitorixConfig->{'graph_enabled'}->{$_}/gm;
	}

	my $rs = $file->set($fileContent);
	return 1 if $rs;

	$file->save();
}

=item _modifyMonitorixCgiFile()

 Modify Monitorix CGI file

 Return int 0 on success, other on failure

=cut

sub _modifyMonitorixCgiFile
{
	my ($self, $action) = @_;

	my $monitorixCgi = '/var/lib/monitorix/www/cgi/monitorix.cgi';

	if(! -f $monitorixCgi) {
		error("File $monitorixCgi is missing.");
		return 1;
	}

	my $file = iMSCP::File->new('filename' => $monitorixCgi);

	my $fileContent = $file->get();
	if(! $fileContent) {
		error('Unable to read $monitorixCgi.');
		return 1;
	}

	my $monitorixCgiConfig = "open(IN, \"< /var/lib/monitorix/www/cgi/monitorix.conf.path\");";
	my $monitorixCgiOldConfig = "open(IN, \"< monitorix.conf.path\");";

	if($action eq 'add') {
		$fileContent =~ s/^open\(IN.*/$monitorixCgiConfig/gm;
	} elsif($action eq 'remove') {
		$fileContent =~ s/^open\(IN.*/$monitorixCgiOldConfig/gm;
	}

	my $rs = $file->set($fileContent);
	return $rs if $rs;

	$file->save();
}

=item _modifyDefaultMonitorixApacheConfig()

 Add or remove /etc/apache2/conf.d/monitorix.conf file

 Return int 0 on success, other on failure

=cut

sub _modifyDefaultMonitorixApacheConfig
{
	my ($self, $action) = @_;

	my $rs = 0;

	my $monitorixBaseDirConfigFile = '/etc/apache2/conf.d/monitorix.conf';
	my $monitorixBackupFile = '/etc/apache2/conf.d/monitorix.old';

	if($action eq 'add') {
		$rs = iMSCP::File->new('filename' => $monitorixBackupFile)->moveFile($monitorixBaseDirConfigFile);
	} elsif($action eq 'remove') {
		$rs = iMSCP::File->new('filename' => $monitorixBaseDirConfigFile)->moveFile($monitorixBackupFile);
	}

	$rs;
}

=item _restartDaemonMonitorix()

 Restart the Monitorix daemon

 Return int 0 on success, other on failure

=cut

sub _restartDaemonMonitorix
{
	my ($stdout, $stderr);
	my $rs = execute("$main::imscpConfig{'SERVICE_MNGR'} monitorix restart", \$stdout, \$stderr);
	debug($stdout) if $stdout;
	error($stderr) if $stderr && $rs;

	$rs;
}

=item _restartDaemonApache()

 Restart the apache daemon

 Return int 0 on success, other on failure

=cut

sub _restartDaemonApache
{
	require Servers::httpd;

	my $httpd = Servers::httpd->factory();

	$httpd->{'restart'} = 'yes';

	0;
}

=item _registerCronjob()

 Register mailgraph cronjob

 Return int 0 on success, other on failure

=cut

sub _registerCronjob
{
	require iMSCP::Database;

	my $rdata = iMSCP::Database->factory()->doQuery(
		'plugin_name', 'SELECT plugin_name, plugin_config FROM plugin WHERE plugin_name = ?', 'Monitorix'
	);
	unless(ref $rdata eq 'HASH') {
		error($rdata);
		return 1;
	}

	require JSON;
	JSON->import();

	my $cronjobConfig = decode_json($rdata->{'Monitorix'}->{'plugin_config'});

	if($cronjobConfig->{'cronjob_enabled'}) {
		my $cronjobFilePath = $main::imscpConfig{'GUI_ROOT_DIR'} . '/plugins/Monitorix/cronjob/cronjob.pl';

		my $cronjobFile = iMSCP::File->new('filename' => $cronjobFilePath);

		my $cronjobFileContent = $cronjobFile->get();
		if(! $cronjobFileContent) {
			error("Unable to read $cronjobFileContent");
			return 1;
		}

		require iMSCP::TemplateParser;
		iMSCP::TemplateParser->import();

		$cronjobFileContent = process(
			{ 'IMSCP_PERLLIB_PATH' => $main::imscpConfig{'ENGINE_ROOT_DIR'} . '/PerlLib' },
			$cronjobFileContent
		);

		my $rs = $cronjobFile->set($cronjobFileContent);
		return $rs if $rs;

		$rs = $cronjobFile->save();
		return $rs if $rs;

		require Servers::cron;
		Servers::cron->factory()->addTask(
			{
				'TASKID' => 'PLUGINS:Monitorix',
				'MINUTE' => $cronjobConfig->{'cronjob_config'}->{'minute'},
				'HOUR' => $cronjobConfig->{'cronjob_config'}->{'hour'},
				'DAY' => $cronjobConfig->{'cronjob_config'}->{'day'},
				'MONTH' => $cronjobConfig->{'cronjob_config'}->{'month'},
				'DWEEK' => $cronjobConfig->{'cronjob_config'}->{'dweek'},
				'COMMAND' => "umask 027; perl $cronjobFilePath >/dev/null 2>&1"
			}
		);
	} else {
		0;
	}
}

=item _unregisterCronjob()

 Unregister mailgraph cronjob

 Return int 0 on success, other on failure

=cut

sub _unregisterCronjob
{
	require Servers::cron;
	Servers::cron->factory()->deleteTask({ 'TASKID' => 'PLUGINS:Monitorix' });
}

=item _checkRequirements

 Check requirements for monitorix plugin

 Return int 0 if all requirements are meet, 1 otherwise

=cut

sub _checkRequirements
{
	my $self = $_[0];

	my $rs = 0;

	if(-f '/etc/apache2/conf.d/monitorix.conf') {
		$rs = $self->_modifyDefaultMonitorixApacheConfig('remove');
		return $rs if $rs;
		
		$rs = $self->_restartDaemonApache();
		return $rs if $rs;
	}
	
	$rs = $self->_modifyMonitorixSystemConfig('add');
	return $rs if $rs;
	
	$rs = $self->_modifyMonitorixSystemConfigEnabledGraphics();
	return $rs if $rs;
	
	$self->_modifyMonitorixCgiFile('add');
}

=back

=head1 AUTHOR

 Sascha Bay <info@space2place.de>

=cut

1;

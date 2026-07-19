use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::ShareDir::Install;

# ship share/ (set_info_jsons prototypes + sample geshtinanna.toml) into the
# dist share dir, reachable at runtime via File::ShareDir::dist_dir.
install_share dist => 'share';

my %WriteMakefileArgs = (
    NAME             => 'App::Geshtinanna',
    AUTHOR           => q{Zane C. Bowers-Hadley <vvelox@vvelox.net>},
    VERSION_FROM     => 'lib/App/Geshtinanna.pm',
    ABSTRACT_FROM    => 'lib/App/Geshtinanna.pm',
    LICENSE          => 'agpl',
    MIN_PERL_VERSION => '5.006',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker'   => '0',
        'File::ShareDir::Install' => '0',
    },
    TEST_REQUIRES => {
        'Test::More' => '0',
    },
    EXE_FILES => [ 'src_bin/geshtinanna' ],
    PREREQ_PM => {
        'Algorithm::Classifier::IsolationForest'         => '0.6.0',
        'Algorithm::Classifier::IsolationForest::Zorita' => '0',
        'Algorithm::EventsPerSecond'                     => '0',
        'App::Cmd'                                        => '0',
        'Carp'                                           => '0',
        'File::ShareDir'                                 => '0',
        'File::Spec'                                     => '0',
        'JSON::MaybeXS'                                  => '0',
        'POE'                                            => '0',
        'Sys::Hostname'                                  => '0',
        'TOML::Tiny'                                     => '0',
        'Time::Local'                                    => '0',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'App-Geshtinanna-*' },
);

# Compatibility with old versions of ExtUtils::MakeMaker
unless (eval { ExtUtils::MakeMaker->VERSION('6.64'); 1 }) {
    my $test_requires = delete $WriteMakefileArgs{TEST_REQUIRES} || {};
    @{$WriteMakefileArgs{PREREQ_PM}}{keys %$test_requires} = values %$test_requires;
}

unless (eval { ExtUtils::MakeMaker->VERSION('6.55_03'); 1 }) {
    my $build_requires = delete $WriteMakefileArgs{BUILD_REQUIRES} || {};
    @{$WriteMakefileArgs{PREREQ_PM}}{keys %$build_requires} = values %$build_requires;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
    unless eval { ExtUtils::MakeMaker->VERSION('6.52'); 1 };
delete $WriteMakefileArgs{MIN_PERL_VERSION}
    unless eval { ExtUtils::MakeMaker->VERSION('6.48'); 1 };
delete $WriteMakefileArgs{LICENSE}
    unless eval { ExtUtils::MakeMaker->VERSION('6.31'); 1 };

WriteMakefile(%WriteMakefileArgs);

package MY;
use File::ShareDir::Install;

sub postamble {
    my $self = shift;
    my @ret = File::ShareDir::Install::postamble($self);
    push @ret, $self->SUPER::postamble(@_) if $self->can('SUPER::postamble');
    return join "\n", @ret;
}

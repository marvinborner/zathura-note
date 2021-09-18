project('zathura-note', 'c',
  version: '0.0.1',
  meson_version: '>=0.43',
  default_options: ['c_std=c99', 'warning_level=3']
)

version = meson.project_version()
version_array = version.split('.')

cc = meson.get_compiler('c')

prefix = get_option('prefix')
datadir = get_option('datadir')
metainfodir = join_paths(datadir, 'metainfo')
desktopdir = join_paths(datadir, 'applications')

# required dependencies
zathura = dependency('zathura', version: '>=0.3.9')
girara = dependency('girara-gtk3')
glib = dependency('glib-2.0')
cairo = dependency('cairo')
zip = dependency('libzip')
plist = dependency('libplist')

build_dependencies = [
  zathura,
  girara,
  glib,
  cairo,
  zip,
  plist
]

plugindir = zathura.get_pkgconfig_variable('plugindir')

# defines
defines = [
  '-DVERSION_MAJOR=@0@'.format(version_array[0]),
  '-DVERSION_MINOR=@0@'.format(version_array[1]),
  '-DVERSION_REV=@0@'.format(version_array[2]),
  '-D_DEFAULT_SOURCE',
]

# compile flags
flags = [
  '-Wall',
  '-Wextra',
  '-pedantic',
  '-Werror=implicit-function-declaration',
  '-Werror=vla',
  '-fvisibility=hidden'
]
flags = cc.get_supported_arguments(flags)

sources = files(
  'zathura-note/plugin.c',
  'zathura-note/note.c'
)

note = shared_module('note',
  sources,
  dependencies: build_dependencies,
  c_args: defines + flags,
  install: true,
  install_dir: plugindir
)

subdir('data')

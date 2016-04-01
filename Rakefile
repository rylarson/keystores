require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rubygems/tasks'

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

#This gives us build, install, and release
Gem::Tasks.new(:console => false, :sign => false)

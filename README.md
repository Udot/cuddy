# Cuddy, the handy deployer

Cuddy is a deployer node. It picks up a queue (jsoned array) in a Redis server using his personal token as key, and then grab each hash in there to do his work.

  ```
      {"version" => integer,       #the version number
       "name" => string,            #the name of the app
       "status" => string,          #starts with "waiting"
       "started_at" => datetime,    #the time when the app was added in the queue
       "finished_at" => datetime,   #the time when the app was properly deployed
       "backoffice" => boolean      # is the app a backoffice thing (will not create db and use different init script)
       "config" => { "unicorn" => { "workers" => integer },
         "db" => {"hostname" => string, "database" => string, "username" => string, "token" => string}
       }
  ```

Cuddy will expect to get a tar file named like : `name-version.tgz` from RackSpace CloudFiles, then it will extract it into `/var/www`. The tar file is expected to have `name/version/` as base path (all the app stuff must be in this path in the tar ball). Once extracted action will depend on the _backoffice_ status of your app.

**NOTE** : cuddy doesn't run a `bundle install` it expects that the tar ball is a _ready to run_ copy of your app. In clear : you must have (one way or another) bundled all the gems of your app with it. *remember* to do such install on a server that has _as close as possible_ installed setup to your hosting server.

## Backoffice

Backoffice status is defined with `"backoffice" => true` in the hash. In this case, cuddy will :

1. call send `QUIT` signal to the running unicorn (located in `/var/www/shared/pids/unicorn-appname.pid`)
2. destroy the previous version symlink if it exists
3. create a symlink named _current_ pointing to the new version in `/var/www/appname`
4. start the unicorn using _bundle exec_ command, passing both `approot/config.ru` and `approot/config/unicorn.rb` files and using _production_ as environment.

## Normal

To come

## Requirements

You need a working _ruby 1.9.2_ environment with at least the _bundler_, _unicorn_ gems installed in there.

## Setup and start

Copy the sample config file and edit it to your needs. Run bundle install, and start the _daemon_ using `ruby cuddy_control start`.

## License

MIT, see License file.

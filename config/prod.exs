import Config

config :tesla, Tesla.Middleware.Logger, debug: false
# Logging configuration is evaluated at compile time, so Tesla must be
# recompiled for the configuration to take effect:
#   mix deps.clean --build tesla
#   mix deps.compile tesla

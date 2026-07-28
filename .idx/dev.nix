# To learn more about how to use Nix to configure your environment
# see: https://developers.google.com/idx/guides/customize-idx-env
{ pkgs, ... }: {
  # Which nixpkgs channel to use.
  channel = "stable-23.11"; # Or your current channel

  # Use https://search.nixos.org/packages to find packages
  packages = [
    pkgs.nodejs_20
    # Add Poppler Utils for PDF rasterization
    pkgs.poppler_utils
  ];

  # Sets environment variables in the workspace
  env = {};

  idx = {
    # Search for the extensions you need https://open-vsx.org/
    extensions = [];

    # Enable previews
    workspace = {
      # Runs when a workspace is first created
      onCreate = {
        npm-install = "npm install";
      };
    };
  };
}

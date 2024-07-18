{ config
, pkgs
, lib
, ... }:

let
  cfg = config.services.emberkeyd;
  emberkeyd = pkgs.callPackage ./default.nix {};
in {

  options.services.emberkeyd = with lib; {
    enable = mkEnableOption "emberkeyd";
    user = mkOption {
      type = types.str;
      default = "emberkeyd";
      description = "The system user the bot runs under";
    };
    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/emberkeyd";
      description = "Path to bot's state directory";
    };
  };

  config = lib.mkIf cfg.enable {

    users.users."${cfg.user}" = {
      group = cfg.user;
      isSystemUser = true;
    }; 
    users.groups."${cfg.user}" = {};

    systemd.services."emberkeyd" = {
      description = "Key Server for Embertalk";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${emberkeyd}/bin/emberkeyd";
        User = cfg.user;
        Type = "simple";
        KillMode = "process";
        Restart = "on-failure";
        WorkingDirectory = cfg.stateDir;
      };
    };
  };
}

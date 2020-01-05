using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using McMaster.Extensions.CommandLineUtils;

namespace TSTool
{
    [Command("TSTool.exe")]
    [VersionOptionFromMember("--version", MemberName = nameof(GetVersion))]
    [Subcommand(
        typeof(GetGracePeriodRawCommand),
        typeof(GetGracePeriodCommand),
        typeof(SetGracePeriodCommand),
        typeof(RestartServicesCommand),
        typeof(ResetGracePeriodCommand)
        )]
    class TsToolMain : TsToolCommandBase
    {
        public static void Main(string[] args) => CommandLineApplication.Execute<TsToolMain>(args);

        protected override int OnExecute(CommandLineApplication app)
        {
            // this shows help even if the --help option isn't specified
            app.ShowHelp();
            return 1;
        }

        public override List<string> CreateArgs()
        {
            var args = new List<string>();
            return args;
        }

        private static string GetVersion()
            => "TSTool.exe " + Assembly.GetExecutingAssembly().GetName().Version;
    }

    [Command(Description = "Get a raw decoded FILETIME byte array of the grace period expiring time")]
    class GetGracePeriodRawCommand : TsToolCommandBase
    {
        private TsToolMain Parent { get; set; }

        protected override int OnExecute(CommandLineApplication app)
        {
            Console.WriteLine(Utils.ByteArrayToString(TerminalService.GetGracePeriodValRaw()));
            return 0;
        }

        public override List<string> CreateArgs()
        {
            var args = Parent.CreateArgs();
            args.Add("GetGracePeriodRaw");
            return args;
        }
    }

    [Command(Description = "Get the grace period expiring time in days")]
    class GetGracePeriodCommand : TsToolCommandBase
    {
        private TsToolMain Parent { get; set; }

        protected override int OnExecute(CommandLineApplication app)
        {
            try
            {
                var ret = TerminalService.GetGracePeriod(out var days);
                Console.WriteLine(days);
                return ret;
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Have you installed / enabled Remote Desktop Services on your machine?");
                return -1;
            }
        }

        public override List<string> CreateArgs()
        {
            var args = Parent.CreateArgs();
            args.Add("GetGracePeriod");
            return args;
        }
    }

    [Command(Description = "Set the grace period expiring time")]
    class SetGracePeriodCommand : TsToolCommandBase
    {
        private TsToolMain Parent { get; set; }

        [Option("--days|-d", "How many days after today shall the evaluation license expire", CommandOptionType.SingleValue)]
        public long? Days { get; set; }

        [Option("--restart-services|-r", "Restart remote desktop services afterwards", CommandOptionType.NoValue)]
        public bool RestartServices { get; set; }

        protected override int OnExecute(CommandLineApplication app)
        {
            if (!Utils.HasAdmin()) Console.WriteLine("Please run this command as Administrator or it might fail!");
            try
            {
                RegistrySecurity oldrs = null;
                if (Days == null) Days = 114515;
                oldrs = TerminalService.SetGracePeriodRegistryKeyPermission();
                TerminalService.SetGracePeriodVal((long)Days);
                Console.WriteLine($"Grace period set to {Days} days");
                if (oldrs != null) TerminalService.SetGracePeriodRegistryKeyPermission(oldrs);
                if (RestartServices) TerminalService.RestartServices();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return -1;
            }

            return 0;
        }

        public override List<string> CreateArgs()
        {
            var args = Parent.CreateArgs();
            args.Add("GetGracePeriod");
            return args;
        }
    }

    [Command(Description = "Reset the grace period information and start over")]
    class ResetGracePeriodCommand : TsToolCommandBase
    {
        private TsToolMain Parent { get; set; }

        [Option("--restart-services|-r", "Restart remote desktop services afterwards", CommandOptionType.NoValue)]
        public bool RestartServices { get; set; }

        protected override int OnExecute(CommandLineApplication app)
        {
            if (!Utils.HasAdmin()) Console.WriteLine("Please run this command as Administrator or it might fail!");
            try
            {
                RegistrySecurity oldrs = null;
                oldrs = TerminalService.SetGracePeriodRegistryKeyPermission();
                TerminalService.ResetGracePeriodVal();
                Console.WriteLine($"Grace period is reset");
                if (oldrs != null) TerminalService.SetGracePeriodRegistryKeyPermission(oldrs);
                if (RestartServices) TerminalService.RestartServices();

            } catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return -1;
            }

            return 0;
        }

        public override List<string> CreateArgs()
        {
            var args = Parent.CreateArgs();
            args.Add("GetGracePeriod");
            return args;
        }
    }

    [Command(Description = "Restart remote desktop services")]
    class RestartServicesCommand : TsToolCommandBase
    {
        private TsToolMain Parent { get; set; }

        [Option("--days", "How many days after today shall the evaluation license expire", CommandOptionType.SingleValue)]
        public long? Days { get; set; }

        protected override int OnExecute(CommandLineApplication app)
        {
            if (!Utils.HasAdmin()) Console.WriteLine("Please run this command as Administrator or it might fail!");
            try
            {
                TerminalService.RestartServices();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to restart services: {ex.Message}");
            }
            return 0;
        }

        public override List<string> CreateArgs()
        {
            var args = Parent.CreateArgs();
            args.Add("RestartServices");
            return args;
        }
    }

    /// <summary>
    /// This base type provides shared functionality.
    /// Also, declaring <see cref="HelpOptionAttribute"/> on this type means all types that inherit from it
    /// will automatically support '--help'
    /// </summary>
    [HelpOption("--help")]
    abstract class TsToolCommandBase
    {
        public abstract List<string> CreateArgs();

        protected virtual int OnExecute(CommandLineApplication app)
        {
            var args = CreateArgs();

            Console.WriteLine("Result = TSTool.exe " + ArgumentEscaper.EscapeAndConcatenate(args));
            return 0;
        }
    }
}

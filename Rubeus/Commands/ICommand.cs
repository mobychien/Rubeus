using System.Collections.Generic;

namespace TDNite.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}
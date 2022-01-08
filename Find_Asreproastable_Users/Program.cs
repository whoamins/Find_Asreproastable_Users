// See https://aka.ms/new-console-template for more information

using Find_Asreproastable_Users;

var searcher = new Searcher();
try
{
    searcher.GetVulnerableUsers(args[0], args[1], args[2]);
}
catch (IndexOutOfRangeException)
{
    Console.WriteLine("Example of usage: Find_Asreproastable_Users.exe domain username password");
}
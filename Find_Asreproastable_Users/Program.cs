using Find_Asreproastable_Users;

var searcher = new AdComminication();

try
{
    var users = searcher.GetVulnerableUsers(args[0], args[1], args[2]);

    if (users == null)
    {
        Console.WriteLine("I haven't found any asreproastable users");
        return 0;
    }
}
catch (IndexOutOfRangeException)
{
    Console.WriteLine("Example of usage: Find_Asreproastable_Users.exe domain username password");
}

Console.WriteLine("Do you want to change userAccountControl to 512 for these users? Y/n");
var userInput = Console.ReadLine();

if (userInput?.ToLower() == "y")
{
    searcher.ChangeSomeProperties(args[0], args[1], args[2]);
}

return 0;
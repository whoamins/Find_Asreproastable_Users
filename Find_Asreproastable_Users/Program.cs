using Find_Asreproastable_Users;

var adCommunication = new AdCommunication(args[0], args[1], args[2]);

try
{
    var users = AdCommunication.ShowVulnerableUsers();

    if (!users) return 0;
}
catch (IndexOutOfRangeException)
{
    Console.WriteLine("Example of usage: Find_Asreproastable_Users.exe domain username password");
}

Console.WriteLine("Do you want to change userAccountControl to 512 for these users? Y/n");
var userInput = Console.ReadLine();

if (userInput?.ToLower() == "y")
{
    AdCommunication.ChangeSomeProperties();
}

return 0;
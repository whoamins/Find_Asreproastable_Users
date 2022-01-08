using LdapForNet;


namespace Find_Asreproastable_Users;

public class Searcher
{
    private LdapConnection? Connect(string domain, string username, string password)
    {
        var cn = new LdapConnection();

        if (domain.Split(".").Length == 1)
        {
            Console.WriteLine("The domain must have TLD\nTrying to add '.com'\n");
            domain += ".com";
        }

        try
        {
            cn.Connect(new Uri($"LDAP://{domain}"));
            cn.Bind(userDn: username, password: password);
        }
        catch (LdapInvalidCredentialsException)
        {
            Console.WriteLine("Invalid Credentials!");
            return null;
        }
        catch (LdapException)
        {
            Console.WriteLine("Can't connect to this domain!");
            return null;
        }

        return cn;
    }
    
    /// <summary>
    /// Returns users vulnerable to asreproasting attack
    /// </summary>
    /// <param name="domain">Domain Controller Domain Name. Example: amazing.dc</param>
    /// <param name="username">Username for LDAP connection</param>
    /// <param name="password">Password for LDAP connection</param>
    public void GetVulnerableUsers(string domain, string username, string password)
    {
        using var cn = Connect(domain, username, password);
        
        if (cn == null) return;

        var splittedDomain = domain.Split('.');
        IList<LdapEntry> entries = new List<LdapEntry>();

        switch (splittedDomain.Length)
        {
            case 3:
                entries = cn.Search($"dc={splittedDomain[0]},dc={splittedDomain[1]},dc={splittedDomain[2]}",
                    "(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304))");
                break;
            case 2:
                entries = cn.Search($"dc={splittedDomain[0]},dc={splittedDomain[1]}",
                    "(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304))");
                break;
        }
        
        if (entries.Count == 0) return;
        
        Console.WriteLine("Vulnerable Users:");
        foreach (var e in entries)
        {
            Console.WriteLine(e.DirectoryAttributes["CN"].GetValue<string>());
        }
    }
}
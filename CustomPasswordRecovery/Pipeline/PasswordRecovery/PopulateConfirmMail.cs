using Sitecore;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.PasswordRecovery;
using Sitecore.Security.Accounts;
using Sitecore.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace CustomPasswordRecovery.Pipeline.PasswordRecovery
{
  public class PopulateConfirmMail : PopulateMail
  {
    public override void Process(PasswordRecoveryArgs args)
    {
      Assert.ArgumentNotNull(args, "args");
      var token = args.CustomData[Constants.ConfirmTokenKey] as string;
      if (string.IsNullOrEmpty(token))
      {
        return;
      }

      var confirmLink = GenerateConfirmLink(token, args.Username);
      args.SendFromDisplayName = "Sitecore website";
      args.SendFromEmail = "noreply@testsite.com";
      args.Subject = "Confirm password recovery";
      var user = User.FromName(args.Username, false);
      args.HtmlEmailContent = GetHtmlEmailContent(user, confirmLink);
    }
    protected virtual string GenerateConfirmLink(string token, string userName)
    {
      var serverUrl = StringUtil.EnsurePostfix('/', WebUtil.GetServerUrl());
      return serverUrl + "api/custompasswordrecovery/confirm?username=" + userName.Replace('\\', '|') + "&token=" + token;
    }
    protected virtual string GetHtmlEmailContent(User user, string confirmLink)
    {
      var sb = new StringBuilder();
      sb.AppendLine("<html><head><title>");
      sb.AppendLine("Sitecore password recovery");
      sb.AppendLine("</title></head><body>");
      sb.AppendLine("<h1>Please confirm</h1>");
      sb.AppendLine("<p>Hi " + user.Profile.FullName + ",<br/></p>");
      sb.AppendLine("<p>Please follow the link below to recover your password</p>");
      sb.AppendLine("<a href=\"" + confirmLink + "\">" + confirmLink + "</a>");
      sb.AppendLine("</body>");
      sb.AppendLine("</html>");
      return sb.ToString();
    }
  }
}
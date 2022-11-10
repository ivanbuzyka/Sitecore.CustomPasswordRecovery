using CustomPasswordRecovery.Pipeline.PasswordRecovery;
using Sitecore.Data;
using Sitecore.Pipelines;
using Sitecore.Pipelines.PasswordRecovery;
using Sitecore.Security.Accounts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Web.Http.Results;
using System.Web.UI.WebControls;

namespace CustomPasswordRecovery.Controllers
{
  [RoutePrefix("api/custompasswordrecovery")]
  public class ConfirmRecoveryController : ApiController
  {
    [Route("confirm")]
    [HttpGet]
    public IHttpActionResult Confirm([FromUri] string userName, [FromUri] string token)
    {
      userName = userName.Replace('|', '\\');
      var user = Sitecore.Security.Accounts.User.FromName(userName, true);
      if (user == null || !TokenIsValid(user, token))
      {
        return new StatusCodeResult(HttpStatusCode.Unauthorized, this);
      }

      var passwordRecoveryArgs = new PasswordRecoveryArgs(HttpContext.Current)
      {
        Username = userName
      };

      PipelineFactory.GetPipeline("confirmPasswordRecovery").Start(passwordRecoveryArgs);
      //CorePipeline.Run("confirmPasswordRecovery", passwordRecoveryArgs);
      if (!passwordRecoveryArgs.Aborted)
      {
        DeleteToken(user);

        // delete attempts history in case the password reset is confirmed
        DeletePasswordResetAttemptsHistory(user);
      }

      return Ok("Password reset confirmed successfully, new password has been sent to your E-Mail");
    }
    private void DeleteToken(User user)
    {
      user.Profile.SetCustomProperty(Constants.ConfirmTokenKey, string.Empty);
      user.Profile.Save();
    }

    private void DeletePasswordResetAttemptsHistory(User user)
    {
      user.Profile.SetCustomProperty(Constants.PasswordResetAttemptsKey, string.Empty);
      user.Profile.Save();
    }

    private bool TokenIsValid(User user, string token)
    {
      return !string.IsNullOrEmpty(token) && ShortID.IsShortID(token) && TokenExists(user, token);
    }

    private bool TokenExists(User user, string confirmToken)
    {
      var tokenOnProfile = user.Profile.GetCustomProperty(Constants.ConfirmTokenKey);
      return !string.IsNullOrEmpty(tokenOnProfile) && tokenOnProfile.Equals(confirmToken, StringComparison.InvariantCultureIgnoreCase);
    }
  }
}

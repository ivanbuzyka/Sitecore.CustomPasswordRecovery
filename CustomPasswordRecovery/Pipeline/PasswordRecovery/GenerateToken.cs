using Sitecore.Data;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.PasswordRecovery;
using Sitecore.Security.Accounts;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web;

namespace CustomPasswordRecovery.Pipeline.PasswordRecovery
{
  public class GenerateToken : PasswordRecoveryProcessor
  {
    public override void Process(PasswordRecoveryArgs args)
    {
      Assert.ArgumentNotNull(args, "args");
      var user = User.FromName(args.Username, true);
      if (user == null)
      {
        args.AbortPipeline();
        return;
      }

      //ToDo check whether since Timestamp in profile is not more than 2 login attempts was executed
      // if yes - throw error and abort pipeline

      // if no - increment 

      ApplyCustomUserProfile(user);
      if (!ValidateAndRecordResetAttempt(user, DateTime.UtcNow))
      {
        Log.Error($"CustomPasswordRecovery: the amount of reset passwords attempts exceeded for user '{user.Name}'. It is possible to try again later", this);
        args.AbortPipeline();
        return;
      }

      var token = ID.NewID.ToShortID().ToString();
      StoreTokenOnUser(user, token);
      args.CustomData.Add(Constants.ConfirmTokenKey, token);
    }
    
    private void ApplyCustomUserProfile(User user)
    {
      user.Profile.ProfileItemId = Constants.ProfileId;
      user.Profile.Save();
    }

    private void StoreTokenOnUser(User user, string confirmToken)
    {
      user.Profile.SetCustomProperty(Constants.ConfirmTokenKey, confirmToken);
      user.Profile.Save();
    }

    private string GetTimestamp(DateTime value)
    {
      return value.ToString("yyyyMMddHHmmssffff", CultureInfo.InvariantCulture);
    }

    private void RecordResetAttempts(User user, List<DateTime> attemptsHistory)
    {
      user.Profile.SetCustomProperty(Constants.PasswordResetAttemptsKey, string.Join("|", attemptsHistory.Select(cc => GetTimestamp(cc))));
      user.Profile.Save();

    }

    // check here whether reset attempt count is not exceeding limit
    private bool ValidateAndRecordResetAttempt(User user, DateTime attemptDateTime)
    {
      var result = true;
      List<DateTime> newAttemptsHistory = new List<DateTime>();

      var passwordResetAttemptsString = user.Profile.GetCustomProperty(Constants.PasswordResetAttemptsKey);
      if (string.IsNullOrEmpty(passwordResetAttemptsString))
      {
        result = true;
      }
      else
      {
        newAttemptsHistory = passwordResetAttemptsString.Split('|').Where(s => !string.IsNullOrEmpty(s)).Select(dt => DateTime.ParseExact(dt, "yyyyMMddHHmmssffff", CultureInfo.InvariantCulture)).ToList();
        if (newAttemptsHistory.Where(x => x > attemptDateTime.AddHours(-Constants.EvaluationRangeInHours)).Count() >= Constants.MaxAllowedResetAttempts)
        {
          // the limit is reached
          result = false;
        }
      }

      newAttemptsHistory.Add(attemptDateTime);

      // save reset attempts history for x 3 more hours than defined in the constant
      RecordResetAttempts(user, newAttemptsHistory.Where(attempt => attempt > attemptDateTime.AddHours(-Constants.EvaluationRangeInHours * 3)).ToList());

      return result;
    }
  }
}

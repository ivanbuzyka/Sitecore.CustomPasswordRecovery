using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CustomPasswordRecovery
{
  public static class Constants
  {
    // core:/sitecore/system/Settings/Security/Profiles/CustomUser
    public const string ProfileId = "{83E843FD-5142-4D93-A2F8-F8426E5128D2}";

    public const string ConfirmTokenKey = "PasswordToken";

    public static string PasswordResetAttemptsKey = "PasswordResetAttempts";

    public static int MaxAllowedResetAttempts
    {
      get
      {
        return Sitecore.Configuration.Settings.GetIntSetting("CustomPasswordReset.maxAllowedResetAttempts", 2);
      }
    }

    public static int EvaluationRangeInHours
    {
      get
      {
        return Sitecore.Configuration.Settings.GetIntSetting("CustomPasswordReset.evaluationRangeInHours", 1);
      }
    }
  }
}
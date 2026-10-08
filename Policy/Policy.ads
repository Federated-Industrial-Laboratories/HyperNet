-- SPDX-License-Identifier: MIT
with Interfaces;
with Interfaces.C;

package Policy with SPARK_Mode, Pure is
   subtype Mask is Interfaces.Unsigned_64;
   subtype Flag is Interfaces.C.unsigned;
   use type Interfaces.Unsigned_64;
   use type Interfaces.C.unsigned;

   function Effective
     (Requested, Network, User, Host, Application : Mask;
      Now, Expires, Current_Epoch, Minimum_Epoch : Mask;
      Host_Active : Flag) return Mask
   with
     Export, Convention => C, External_Name => "HyperNetEffectivePolicy",
     Global => null,
     Depends => (Effective'Result =>
       (Requested, Network, User, Host, Application, Now, Expires,
        Current_Epoch, Minimum_Epoch, Host_Active)),
     Post =>
       (if Host_Active /= 1 or else Now >= Expires
           or else Current_Epoch < Minimum_Epoch
        then Effective'Result = 0
        else Effective'Result =
          (Requested and Network and User and Host and Application))
       and then (Effective'Result and not Requested) = 0
       and then (Effective'Result and not Network) = 0
       and then (Effective'Result and not User) = 0
       and then (Effective'Result and not Host) = 0
       and then (Effective'Result and not Application) = 0;
end Policy;

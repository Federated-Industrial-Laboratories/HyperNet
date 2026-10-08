-- SPDX-License-Identifier: MIT
package body Policy with SPARK_Mode is
   function Effective
     (Requested, Network, User, Host, Application : Mask;
      Now, Expires, Current_Epoch, Minimum_Epoch : Mask;
      Host_Active : Flag) return Mask
   is
   begin
      if Host_Active /= 1 or else Now >= Expires
        or else Current_Epoch < Minimum_Epoch
      then
         return 0;
      end if;
      return Requested and Network and User and Host and Application;
   end Effective;
end Policy;

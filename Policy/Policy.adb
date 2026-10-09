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
   function Media_Chunk (Total, Offset, Count : Mask) return Flag is
   begin
      if Total = 0 or else Total > 786432 or else Offset >= Total
        or else Offset mod 32768 /= 0 or else Count = 0
        or else Count > 32768 or else Count > Total - Offset
      then
         return 0;
      end if;
      if Count /= Mask'Min (32768, Total - Offset) then
         return 0;
      end if;
      return 1;
   end Media_Chunk;
end Policy;

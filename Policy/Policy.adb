-- SPDX-License-Identifier: MIT
package body Policy with SPARK_Mode is
   function Media_Range (Total, Offset, Count : Mask) return Flag is
   begin
      if Total = 0 or else Total > 786432 or else Offset >= Total
        or else Count = 0 or else Count > 32768
        or else Count > Total - Offset
      then
         return 0;
      end if;
      return 1;
   end Media_Range;
end Policy;

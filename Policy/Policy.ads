-- SPDX-License-Identifier: MIT
with Interfaces;
with Interfaces.C;

package Policy with SPARK_Mode, Pure is
   subtype Mask is Interfaces.Unsigned_64;
   subtype Flag is Interfaces.C.unsigned;
   use type Interfaces.Unsigned_64;
   use type Interfaces.C.unsigned;

   function Media_Range (Total, Offset, Count : Mask) return Flag
   with
     Export, Convention => C, External_Name => "HyperNetMediaRange",
     Global => null,
     Depends => (Media_Range'Result => (Total, Offset, Count)),
     Post => (Media_Range'Result <= 1)
       and then (if Media_Range'Result = 1 then
         Total > 0 and then Total <= 786432 and then Offset < Total
         and then Count > 0 and then Count <= 32768
         and then Count <= Total - Offset);
end Policy;

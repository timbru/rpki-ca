/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.scenarios

import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.app.main.Dsl._
import org.joda.time.DateTime

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PerformanceTest extends RpkiTest {

  import scala.language.postfixOps

  /**
    *
    * KeyPair generation is the biggest performance problem. 2048 bit keys take a long time
    * without any special hardware.
    *
    * Used this test to measure performance before and after extending the
    * KeyPairSupport object with logic to pre-generate keys in paralel, utilising
    * all cores (or well threads in the global thread pool).
    *
    * Ignoring this test here, because it takes 20 seconds to run, but leaving the code for future use.
    *
    * Manual testing found that on my quad core machine the performance
    * of creating and certifying a new CA is improved by a factor of..
    * perhaps unsurprisingly.. four. From ~2.1 second / CA to ~0.6 second / CA.
    *
    * BTW new certified CAs set up this way need two keypairs: one for the identity cert,
    * and one for the resource cert
    *
    */
  ignore("Improve performance of CA generatiom") {
    create trustAnchor ()

    create certificateAuthority ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources "10.0.0.0/8"
    certificateAuthority withId ChildId addTa(current trustAnchor)
    certificateAuthority withId ChildId update

    val timeBeforeGrandChildren = new DateTime()

    val grandChildIds = for (child <- 1 to 25) yield {
      val id = UUID.randomUUID()
      val resources: IpResourceSet = "10.0." + child + ".0/24"

      create certificateAuthority id
      certificateAuthority withId ChildId addChild(current certificateAuthority id) withResources resources
      certificateAuthority withId id addParent(current certificateAuthority ChildId)
      certificateAuthority withId id update

      id
    }

    val timePerCaCreate: Long = (new DateTime().getMillis - timeBeforeGrandChildren.getMillis) / grandChildIds.size

    (timePerCaCreate < 2000) should be (true) // Should be less than 2 seconds per CA
  }



}

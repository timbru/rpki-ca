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
package nl.bruijnzeels.tim.rpki

import java.net.URI

import net.ripe.ipresource.{Asn, IpRange, IpResourceSet}
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix
import nl.bruijnzeels.tim.rpki.common.cqrs.EventStore
import org.scalatest.{BeforeAndAfter, FunSuite, Matchers}

import scala.language.implicitConversions

/**
 * Base class for testing. Wipes the EventStore. Do NOT run tests that rely on this in paralel.
 */
abstract class RpkiTest extends FunSuite with Matchers with BeforeAndAfter {

  before {
    EventStore.clear
  }

  def time[R](block: => R): TimeResult[R] = {
    val t0 = System.nanoTime()
    val result = block    // call-by-name
    val t1 = System.nanoTime()
    TimeResult(t1-t0, result)
  }


  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)
  implicit def stringToIpRange(s: String): IpRange =  IpRange.parse(s)
  implicit def stringToPrefix(s: String): RoaPrefix =  new RoaPrefix(IpRange.parse(s))
  implicit def stringToAsn(s: String): Asn = Asn.parse(s)
  implicit def stringToUri(s: String): URI = URI.create(s)

}

case class TimeResult[R](timeInNs: Long, result: R)
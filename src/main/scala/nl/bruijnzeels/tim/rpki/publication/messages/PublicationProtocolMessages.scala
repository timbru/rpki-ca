/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.publication.messages

import java.net.URI
import scala.xml.Elem
import scala.xml.XML
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.ValidationResult
import sun.misc.BASE64Decoder
import sun.misc.BASE64Encoder
import java.math.BigInteger
import java.util.UUID
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import org.apache.commons.lang3.StringUtils
import java.nio.charset.Charset

sealed trait DeltaProtocolMessage {
  def toXml: Elem
}

case class Notification(sessionId: UUID, serial: BigInteger, snapshot: SnapshotReference, deltas: List[DeltaReference] = List.empty) extends DeltaProtocolMessage {
  def toXml =
    <notification xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id={ sessionId.toString } serial={ serial.toString }>
      { snapshot.toXml }
      { deltas.map(_.toXml) }
    </notification>
}

case class SnapshotReference(uri: URI, hash: ReferenceHash) {
  def toXml = <snapshot uri={ uri.toString } hash={ hash.toString }/>
}

case class DeltaReference(uri: URI, serial: BigInteger, hash: ReferenceHash) {
  def toXml = <delta serial={ serial.toString } uri={ uri.toString } hash={ hash.toString }/>
}

case class ReferenceHash(hash: String) {
  def matches(other: Array[Byte]): Boolean = StringUtils.equals(hash, ReferenceHash.fromBytes(other).hash)
  override def toString = hash
}

object ReferenceHash {
  def fromBytes(bytes: Array[Byte]) = {
    ReferenceHash(ManifestCms.hashContents(bytes).map("%02X" format _).mkString)
  }

  def fromXml(xml: Elem) = {
    val bytes = xml.toString.getBytes(Charset.forName("UTF8"))
    fromBytes(bytes)
  }
}

case class Snapshot(sessionId: UUID, serial: BigInteger, publishes: List[Publish]) extends DeltaProtocolMessage {

  def toXml =
    <snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id={ sessionId.toString } serial={ serial.toString }>
      { for (publish <- publishes) yield { publish.toXmlWithoutHash } }
    </snapshot>

}

case class Delta(sessionId: UUID, serial: BigInteger, messages: List[PublicationProtocolMessage]) extends DeltaProtocolMessage {

  def toXml =
    <delta xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id={ sessionId.toString } serial={ serial.toString }>
      { for (message <- messages) yield { message.toXml } }
    </delta>

}

sealed trait PublicationProtocolMessage {
  def toXml: Elem
}

case class Publish(uri: URI, replaces: Option[ReferenceHash], repositoryObject: CertificateRepositoryObject) extends PublicationProtocolMessage {
  override def toXml = replaces match {
    case None => toXmlWithoutHash
    case Some(hash) => <publish uri={ uri.toString } hash={ hash.toString }>{ new BASE64Encoder().encode(repositoryObject.getEncoded()) }</publish>
  }

  /**
   * In shapshot XML files we do not want to include the old object hashes
   */
  def toXmlWithoutHash = <publish uri={ uri.toString }>{ new BASE64Encoder().encode(repositoryObject.getEncoded()) }</publish>

}

object Publish {

  def fromXml(xml: Elem) = {
    val uri = URI.create((xml \ "@uri").text)

    val repositoryObject = {
      val result = ValidationResult.withLocation(uri)
      val bytes = new BASE64Decoder().decodeBuffer(xml.text)
      CertificateRepositoryObjectFactory.createCertificateRepositoryObject(bytes, result)
    }

    val replaces = {
      val hash = (xml \ "@hash").text
      if (hash == null || hash.length == 0) {
        None
      } else {
        Some(ReferenceHash(hash = hash))
      }
    }

    Publish(uri, replaces, repositoryObject)
  }

  def fromXmlString(xmlString: String) = fromXml(XML.loadString(xmlString))

  def forRepositoryObject(uri: URI, repositoryObject: CertificateRepositoryObject, oldObject: Option[CertificateRepositoryObject] = None) = {
    val replaces = oldObject.map(cro => ReferenceHash.fromBytes(cro.getEncoded))
    Publish(uri, replaces, repositoryObject)
  }
}

case class Withdraw(uri: URI, hash: ReferenceHash) extends PublicationProtocolMessage {
  override def toXml = <withdraw uri={ uri.toString } hash={ hash.toString }/>
}

object Withdraw {
  def fromXml(xml: Elem) = Withdraw(uri = URI.create((xml \ "@uri").text), hash = ReferenceHash((xml \ "@hash").text))
  def fromXmlString(xmlString: String) = fromXml(XML.loadString(xmlString))
  def forRepositoryObject(uri: URI, repositoryObject: CertificateRepositoryObject) = Withdraw(uri = uri, hash = ReferenceHash.fromBytes(repositoryObject.getEncoded))
}

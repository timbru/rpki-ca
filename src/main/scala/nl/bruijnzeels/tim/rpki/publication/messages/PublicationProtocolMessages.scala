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

case class Notification(sessionId: UUID, serial: BigInteger, snapshots: List[SnapshotReference] = List.empty, deltas: List[DeltaReference] = List.empty) extends DeltaProtocolMessage {

  def toXml =
<notification xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id={ sessionId.toString } serial={ serial.toString }>
{ for (snapshot <- snapshots) yield {
      <snapshot serial={ snapshot.serial.toString } uri={ snapshot.uri.toString } hash={ snapshot.hash.toString }/>
    }
}
{ for (delta <- deltas) yield {
      <delta from={ delta.from.toString } to={ delta.to.toString } uri={ delta.uri.toString } hash={ delta.hash.toString }/>
    }
  }
</notification>
}

case class SnapshotReference(uri: URI, serial: BigInteger, hash: ReferenceHash)
case class DeltaReference(uri: URI, from: BigInteger, to: BigInteger, hash: ReferenceHash)

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
      { for (publish <- publishes) yield { publish.toXml } }
    </snapshot>

}

case class Deltas(sessionId: UUID, from: BigInteger, to: BigInteger, deltas: List[Delta]) extends DeltaProtocolMessage {

  def toXml =
    <deltas xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id={ sessionId.toString } from={ from.toString } to={ to.toString }>
      { for (delta <- deltas) yield { delta.toXml } }
    </deltas>

}

case class Delta(serial: BigInteger, messages: List[PublicationProtocolMessage]) extends DeltaProtocolMessage {

  def toXml =
    <delta serial={ serial.toString }>
      { for (message <- messages) yield { message.toXml } }
    </delta>

}

sealed trait PublicationProtocolMessage {
  def toXml: Elem
}

case class Publish(uri: URI, replaces: Option[ReferenceHash], repositoryObject: CertificateRepositoryObject) extends PublicationProtocolMessage {
  override def toXml = replaces match {
    case None => <publish uri={ uri.toString }>{ new BASE64Encoder().encode(repositoryObject.getEncoded()) }</publish>
    case Some(hash) => <publish uri={ uri.toString } replaces={ hash.toString }>{ new BASE64Encoder().encode(repositoryObject.getEncoded()) }</publish>
  }

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
      val hash = (xml \ "@replaces").text
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

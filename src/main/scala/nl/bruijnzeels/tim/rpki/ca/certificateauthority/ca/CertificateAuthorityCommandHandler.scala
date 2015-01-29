package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommand
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

object CertificateAuthorityCommandDispatcher {

  def load(id: UUID): Option[CertificateAuthority] = {
    val events = EventStore.retrieve(id)
    if (events.size == 0) {
      None
    } else {
      Some(CertificateAuthority.rebuild(events).clearEventList())
    }
  }

  def save(ca: CertificateAuthority) = {
    EventStore.store(ca.events, ca.versionedId.next)
  }

  def dispatch(command: CertificateAuthorityCommand) = {
    val caId = command.versionedId.id
    val existingCa = load(caId)

    if (existingCa.isDefined && command.isInstanceOf[CertificateAuthorityCreate]) {
      throw new IllegalArgumentException(s"Can't create new CA with id ${caId} CA with same id exists")
    }

    if (!existingCa.isDefined && !command.isInstanceOf[CertificateAuthorityCreate]) {
      throw new IllegalArgumentException(s"Can't find exisiting CA with id ${caId} for command")
    }

    val updatedCa = command match {
      case create: CertificateAuthorityCreate => CertificateAuthorityCreateHandler.handle(create)
      case addParent: CertificateAuthorityAddParent => CertificateAuthorityAddParentHandler.handle(addParent, existingCa.get)
      case publish: CertificateAuthorityPublish => CertificateAuthorityPublishHandler.handle(publish, existingCa.get)
    }

    save(updatedCa)
    updatedCa
  }
}

object CertificateAuthorityCreateHandler {
  def handle(create: CertificateAuthorityCreate) = CertificateAuthority.create(create.aggregateId, create.name, create.baseUrl, create.rrdpNotifyUrl)
}

trait CertificateAuthorityCommandHandler[C <: CertificateAuthorityCommand] {
  def handle(command: C, ca: CertificateAuthority): CertificateAuthority
}

object CertificateAuthorityAddParentHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityAddParent] {
  override def handle(command: CertificateAuthorityAddParent, ca: CertificateAuthority) = ca.addParent(command.parentXml)
}

object CertificateAuthorityPublishHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityPublish] {
  override def handle(command: CertificateAuthorityPublish, ca: CertificateAuthority) = ca.publish
}
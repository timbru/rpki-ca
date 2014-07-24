package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca

import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommand
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore

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
    EventStore.store(ca.events)
  }

  def dispatch(command: CertificateAuthorityCommand) = {
    val existingCa = load(command.id)

    if (existingCa.isDefined && command.isInstanceOf[CertificateAuthorityCreate]) {
      throw new IllegalArgumentException("Can't create new CA with id " + command.id + ", TA with same id exists")
    }

    if (!existingCa.isDefined && !command.isInstanceOf[CertificateAuthorityCreate]) {
      throw new IllegalArgumentException("Can't find exisiting CA with id " + command.id + " for command")
    }

    val updatedCa = command match {
      case create: CertificateAuthorityCreate => CertificateAuthorityCreateHandler.handle(create)
      case addParent: CertificateAuthorityAddParent => CertificateAuthorityAddParentHandler.handle(addParent, existingCa.get)
    }

    save(updatedCa)
    updatedCa
  }
}


object CertificateAuthorityCreateHandler {
  def handle(create: CertificateAuthorityCreate) = CertificateAuthority.create(create.id, create.name)
}

trait CertificateAuthorityCommandHandler[C <: CertificateAuthorityCommand] {
  def handle(command: C, ca: CertificateAuthority): CertificateAuthority
}

object CertificateAuthorityAddParentHandler extends CertificateAuthorityCommandHandler[CertificateAuthorityAddParent] {
  override def handle(command: CertificateAuthorityAddParent, ca: CertificateAuthority) = ca.addParent(command.parentXml)
}

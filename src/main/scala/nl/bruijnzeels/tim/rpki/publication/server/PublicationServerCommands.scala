package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import nl.bruijnzeels.tim.rpki.publication.messages.PublicationProtocolMessage

sealed trait PublicationServerCommand extends Command {
  def id: UUID
}

case class PublicationServerCreate(id: UUID) extends PublicationServerCommand
case class PublicationServerPublish(id: UUID, messages: List[PublicationProtocolMessage]) extends PublicationServerCommand
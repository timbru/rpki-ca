package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.ipresource.IpResourceSet
import java.net.URI
import java.util.UUID

sealed trait TaCommand extends Command {
  def id: UUID
}

case class TaCreate(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI) extends TaCommand
case class TaPublish(id: UUID) extends TaCommand

case class TaChildAdd(id: UUID, childId: UUID) extends TaCommand

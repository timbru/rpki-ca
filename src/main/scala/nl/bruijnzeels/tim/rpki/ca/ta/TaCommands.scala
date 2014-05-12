package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.ipresource.IpResourceSet

sealed trait TaCommand extends Command

case class CreateTa(name: String, resources: IpResourceSet) extends TaCommand

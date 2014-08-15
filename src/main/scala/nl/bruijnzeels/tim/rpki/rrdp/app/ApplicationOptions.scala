package nl.bruijnzeels.tim.rpki.rrdp.app

import com.typesafe.config.{ ConfigFactory, Config }

object ApplicationOptions {

  private val config: Config = ConfigFactory.load()

  def httpPort: Int = config.getInt("ui.http.port")

}
require "active_record"

module DeviseMultiFactor
  module Orm
    module ActiveRecord
      module Schema
        include DeviseMultiFactor::Schema
      end
    end
  end
end

ActiveRecord::ConnectionAdapters::Table.send :include, DeviseMultiFactor::Orm::ActiveRecord::Schema
ActiveRecord::ConnectionAdapters::TableDefinition.send :include, DeviseMultiFactor::Orm::ActiveRecord::Schema
